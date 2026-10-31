// Package registry resolves image tags to manifest digests with HEAD requests, which
// Docker Hub doesn't count against its pull limits. It speaks the OCI distribution API
// with anonymous or credentialed bearer tokens and needs nothing beyond the standard
// library.
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// ErrRateLimited is returned when the registry answers 429.
var ErrRateLimited = errors.New("registry rate limit reached")

// ErrNotFound is returned when the repository or tag doesn't exist.
var ErrNotFound = errors.New("image or tag not found")

const acceptManifests = "application/vnd.oci.image.index.v1+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.oci.image.manifest.v1+json, " +
	"application/vnd.docker.distribution.manifest.v2+json"

// Ref is a parsed image reference.
type Ref struct {
	Registry   string // host, e.g. registry-1.docker.io
	Repository string // e.g. library/php
	Tag        string // tag; "" when only a digest was given
	Digest     string
}

// String renders the reference with the registry host.
func (r Ref) String() string {
	s := r.Registry + "/" + r.Repository
	if r.Digest != "" {
		return s + "@" + r.Digest
	}
	return s + ":" + r.Tag
}

// ParseRef parses references such as "php:8.4-apache", "nextcloud",
// "linuxserver/nextcloud:latest", "ghcr.io/org/app:1.2" and "repo@sha256:…".
func ParseRef(s string) (Ref, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "registry:"))
	if s == "" {
		return Ref{}, errors.New("empty image reference")
	}
	in := s
	var r Ref
	if i := strings.Index(s, "@"); i >= 0 {
		r.Digest = s[i+1:]
		s = s[:i]
		if r.Digest == "" {
			return Ref{}, fmt.Errorf("invalid image reference %q: empty digest", in)
		}
	}
	// The first path component is a registry host if it contains "." or ":" or is "localhost".
	host := "docker.io"
	if i := strings.Index(s, "/"); i >= 0 {
		first := s[:i]
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			host, s = first, s[i+1:]
		}
	}
	// A reference can carry both a tag and a digest (php:8.4-apache@sha256:...).
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.Contains(s[i:], "/") {
		r.Tag, s = s[i+1:], s[:i]
		if r.Tag == "" {
			return Ref{}, fmt.Errorf("invalid image reference %q: empty tag", in)
		}
	} else if r.Digest == "" {
		r.Tag = "latest"
	}
	// Each path component of the repository must be non-empty, without ":" or spaces.
	for _, c := range strings.Split(s, "/") {
		if c == "" || strings.ContainsFunc(c, func(r rune) bool { return r == ':' || unicode.IsSpace(r) }) {
			return Ref{}, fmt.Errorf("invalid image reference %q", in)
		}
	}
	if host == "docker.io" || host == "index.docker.io" || host == "registry-1.docker.io" {
		host = "registry-1.docker.io"
		if !strings.Contains(s, "/") {
			s = "library/" + s
		}
	}
	r.Registry, r.Repository = host, s
	return r, nil
}

// Client resolves digests. The zero value works anonymously.
type Client struct {
	HTTP *http.Client
	// Username and Password authenticate token requests to Docker Hub, which raises
	// rate limits. They default to DOCKERHUB_USERNAME and DOCKERHUB_TOKEN.
	Username, Password string
	// Scheme is "https" unless set (tests use "http").
	Scheme string

	mu     sync.Mutex
	tokens map[string]cachedToken // key: registry|realm|service|scope
	now    func() time.Time       // tests replace it
}

// cachedToken is a bearer token and when to stop using it. Registries give tokens a
// short life (Docker Hub: 300 seconds), shorter than a cluster check can take.
type cachedToken struct {
	value   string
	expires time.Time
}

// NewClient returns a client with credentials from the environment.
func NewClient() *Client {
	return &Client{
		HTTP:     &http.Client{Timeout: 30 * time.Second},
		Username: os.Getenv("DOCKERHUB_USERNAME"),
		Password: os.Getenv("DOCKERHUB_TOKEN"),
	}
}

// Digest returns the manifest digest the tag currently points to. For a multi-platform
// image this is the digest of the index, which changes whenever any platform changes.
func (c *Client) Digest(ctx context.Context, ref Ref) (string, error) {
	if ref.Digest != "" {
		return ref.Digest, nil
	}
	scheme := c.Scheme
	if scheme == "" {
		scheme = "https"
	}
	u := fmt.Sprintf("%s://%s/v2/%s/manifests/%s", scheme, ref.Registry, ref.Repository, url.PathEscape(ref.Tag))

	resp, err := c.head(ctx, u, "")
	if err != nil {
		return "", err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		challenge := resp.Header.Get("Www-Authenticate")
		token, cached, err := c.token(ctx, challenge, ref, false)
		if err != nil {
			return "", err
		}
		resp, err = c.head(ctx, u, token)
		if err != nil {
			return "", err
		}
		// A cached token can be rejected before its stated expiry; get a fresh one once.
		if resp.StatusCode == http.StatusUnauthorized && cached {
			if token, _, err = c.token(ctx, challenge, ref, true); err != nil {
				return "", err
			}
			if resp, err = c.head(ctx, u, token); err != nil {
				return "", err
			}
		}
	}
	switch resp.StatusCode {
	case http.StatusOK:
		d := resp.Header.Get("Docker-Content-Digest")
		if d == "" {
			return "", fmt.Errorf("%s: registry returned no digest", ref)
		}
		return d, nil
	case http.StatusNotFound:
		return "", fmt.Errorf("%s: %w", ref, ErrNotFound)
	case http.StatusTooManyRequests:
		return "", fmt.Errorf("%s: %w", ref, ErrRateLimited)
	}
	return "", fmt.Errorf("%s: registry answered %s", ref, resp.Status)
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) head(ctx context.Context, u, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", acceptManifests)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return resp, nil
}

// token fetches (and caches until shortly before it expires) a bearer token for the
// challenge, and says whether it came from the cache. With fresh set, it ignores the
// cache.
func (c *Client) token(ctx context.Context, challenge string, ref Ref, fresh bool) (string, bool, error) {
	params := parseChallenge(challenge)
	realm := params["realm"]
	if realm == "" {
		return "", false, fmt.Errorf("%s: registry asked for unsupported authentication %q", ref, challenge)
	}
	// The realm comes from the registry, which in cluster mode anyone who can create
	// a pod chooses. Tokens are fetched only over https (http only in tests).
	realmURL, err := url.Parse(realm)
	if err != nil || realmURL.Host == "" || realmURL.User != nil || (realmURL.Scheme != "https" && !(c.Scheme == "http" && realmURL.Scheme == "http")) {
		return "", false, fmt.Errorf("%s: registry asked for a token from %q, which isn't allowed: it must be an https URL with a host and no user", ref, realm)
	}
	scope := params["scope"]
	if scope == "" {
		scope = "repository:" + ref.Repository + ":pull"
	}
	// A token belongs to the registry that asked for it: a token made with the
	// Docker Hub credentials must never be sent to another registry that names the
	// same realm in its challenge.
	key := ref.Registry + "|" + realm + "|" + params["service"] + "|" + scope
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	c.mu.Lock()
	if t, ok := c.tokens[key]; ok && !fresh && now().Before(t.expires) {
		c.mu.Unlock()
		return t.value, true, nil
	}
	c.mu.Unlock()

	q := url.Values{}
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	q.Set("scope", scope)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm+"?"+q.Encode(), nil)
	if err != nil {
		return "", false, err
	}
	if c.Username != "" && c.Password != "" && dockerHubAuth(ref, realmURL) {
		req.SetBasicAuth(c.Username, c.Password)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return "", false, fmt.Errorf("%s: %w", ref, ErrRateLimited)
	}
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("%s: token request answered %s", ref, resp.Status)
	}
	var body struct {
		Token       string          `json:"token"`
		AccessToken string          `json:"access_token"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", false, fmt.Errorf("%s: bad token response: %w", ref, err)
	}
	t := body.Token
	if t == "" {
		t = body.AccessToken
	}
	life := tokenLife(body.ExpiresIn)
	c.mu.Lock()
	if c.tokens == nil {
		c.tokens = map[string]cachedToken{}
	}
	c.tokens[key] = cachedToken{value: t, expires: now().Add(life)}
	c.mu.Unlock()
	return t, false, nil
}

// dockerHubAuth reports whether the Docker Hub credentials may go with this token
// request: only for a Docker Hub image, and only to Docker Hub's own token service.
func dockerHubAuth(ref Ref, realm *url.URL) bool {
	return ref.Registry == "registry-1.docker.io" && realm.Scheme == "https" && realm.Host == "auth.docker.io"
}

// tokenLife reads expires_in, which registries send as a number or a string, and
// returns how long to use the token: a little less than its life, at most an hour.
// The token spec's default life is 60 seconds.
func tokenLife(raw json.RawMessage) time.Duration {
	secs, err := strconv.ParseFloat(strings.Trim(string(raw), `"`), 64)
	if err != nil || secs <= 0 || math.IsNaN(secs) {
		secs = 60
	}
	life := time.Duration(min(secs, 3600)) * time.Second
	if life > 30*time.Second {
		life -= 15 * time.Second
	}
	return life
}

// parseChallenge parses `Bearer realm="…",service="…",scope="…"`.
func parseChallenge(h string) map[string]string {
	out := map[string]string{}
	h = strings.TrimSpace(h)
	if i := strings.Index(h, " "); i >= 0 {
		h = h[i+1:]
	}
	for len(h) > 0 {
		eq := strings.Index(h, "=")
		if eq < 0 {
			break
		}
		k := strings.TrimSpace(strings.TrimLeft(h[:eq], ", "))
		h = h[eq+1:]
		var v string
		if strings.HasPrefix(h, `"`) {
			end := strings.Index(h[1:], `"`)
			if end < 0 {
				v, h = h[1:], ""
			} else {
				v, h = h[1:end+1], h[end+2:]
			}
		} else if c := strings.Index(h, ","); c >= 0 {
			v, h = h[:c], h[c+1:]
		} else {
			v, h = h, ""
		}
		out[strings.ToLower(k)] = v
	}
	return out
}
