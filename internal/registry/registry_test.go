package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestParseRef(t *testing.T) {
	cases := []struct{ in, reg, repo, tag, digest string }{
		{"php:8.4-apache", "registry-1.docker.io", "library/php", "8.4-apache", ""},
		{"nextcloud", "registry-1.docker.io", "library/nextcloud", "latest", ""},
		{"linuxserver/nextcloud:latest", "registry-1.docker.io", "linuxserver/nextcloud", "latest", ""},
		{"docker.io/library/php:8.3", "registry-1.docker.io", "library/php", "8.3", ""},
		{"ghcr.io/org/app:1.2", "ghcr.io", "org/app", "1.2", ""},
		{"localhost:5000/app", "localhost:5000", "app", "latest", ""},
		{"php@sha256:abc", "registry-1.docker.io", "library/php", "", "sha256:abc"},
		{"registry:php:8.5-fpm", "registry-1.docker.io", "library/php", "8.5-fpm", ""},
		{"php:8.4-apache@sha256:abc", "registry-1.docker.io", "library/php", "8.4-apache", "sha256:abc"},
	}
	for _, c := range cases {
		r, err := ParseRef(c.in)
		if err != nil {
			t.Fatalf("ParseRef(%q): %v", c.in, err)
		}
		if r.Registry != c.reg || r.Repository != c.repo || r.Tag != c.tag || r.Digest != c.digest {
			t.Errorf("ParseRef(%q) = %+v", c.in, r)
		}
	}
}

func TestParseRefRejects(t *testing.T) {
	for _, in := range []string{"", " ", ":", "@", "php:", "php@", "/php", "php/", "a//b", "ghcr.io/", "ghcr.io/a b", "x/a:b/c"} {
		if r, err := ParseRef(in); err == nil {
			t.Errorf("ParseRef(%q) = %+v, want an error", in, r)
		}
	}
}

func TestParseChallenge(t *testing.T) {
	p := parseChallenge(`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/php:pull"`)
	if p["realm"] != "https://auth.docker.io/token" || p["service"] != "registry.docker.io" || p["scope"] != "repository:library/php:pull" {
		t.Fatalf("got %v", p)
	}
}

// fakeRegistry requires a bearer token, like Docker Hub.
func fakeRegistry(t *testing.T, status int) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			if r.URL.Query().Get("scope") != "repository:library/php:pull" {
				t.Errorf("unexpected scope %q", r.URL.Query().Get("scope"))
			}
			w.Write([]byte(`{"token":"t0k"}`))
		case strings.HasPrefix(r.URL.Path, "/v2/"):
			if r.Method != http.MethodHead {
				t.Errorf("expected HEAD, got %s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer t0k" {
				w.Header().Set("Www-Authenticate", `Bearer realm="`+srv.URL+`/token",service="test",scope="repository:library/php:pull"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if status != http.StatusOK {
				w.WriteHeader(status)
				return
			}
			w.Header().Set("Docker-Content-Digest", "sha256:feed")
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return srv
}

func TestDigestWithTokenFlow(t *testing.T) {
	srv := fakeRegistry(t, http.StatusOK)
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), Scheme: "http"}
	ref := Ref{Registry: strings.TrimPrefix(srv.URL, "http://"), Repository: "library/php", Tag: "8.4-apache"}
	d, err := c.Digest(context.Background(), ref)
	if err != nil || d != "sha256:feed" {
		t.Fatalf("got %q, %v", d, err)
	}
	// The token is cached for the second call.
	if d, err := c.Digest(context.Background(), ref); err != nil || d != "sha256:feed" {
		t.Fatalf("second call: %q, %v", d, err)
	}
}

func TestDigestErrors(t *testing.T) {
	for status, want := range map[int]error{http.StatusNotFound: ErrNotFound, http.StatusTooManyRequests: ErrRateLimited} {
		srv := fakeRegistry(t, status)
		c := &Client{HTTP: srv.Client(), Scheme: "http"}
		_, err := c.Digest(context.Background(), Ref{Registry: strings.TrimPrefix(srv.URL, "http://"), Repository: "library/php", Tag: "x"})
		srv.Close()
		if !errors.Is(err, want) {
			t.Errorf("status %d: got %v, want %v", status, err, want)
		}
	}
}

// Tokens expire (Docker Hub's after 300 seconds) and a cluster check can take longer:
// an expired token is replaced, and a rejected cached token is replaced once.
func TestDigestTokenExpiry(t *testing.T) {
	issued, valid := 0, ""
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			issued++
			valid = fmt.Sprintf("t%d", issued)
			fmt.Fprintf(w, `{"token":%q,"expires_in":300}`, valid)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+valid {
			w.Header().Set("Www-Authenticate", `Bearer realm="`+srv.URL+`/token",service="test",scope="repository:library/php:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Docker-Content-Digest", "sha256:feed")
	}))
	defer srv.Close()
	clock := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	c := &Client{HTTP: srv.Client(), Scheme: "http", now: func() time.Time { return clock }}
	ref := Ref{Registry: strings.TrimPrefix(srv.URL, "http://"), Repository: "library/php", Tag: "8.4-apache"}
	digest := func() {
		t.Helper()
		if d, err := c.Digest(context.Background(), ref); err != nil || d != "sha256:feed" {
			t.Fatalf("got %q, %v", d, err)
		}
	}
	digest()
	clock = clock.Add(2 * time.Minute)
	digest() // cached
	if issued != 1 {
		t.Fatalf("%d tokens, want 1 while the first is valid", issued)
	}
	clock = clock.Add(5 * time.Minute)
	digest() // expired: a new token without a failed request
	if issued != 2 {
		t.Fatalf("%d tokens, want 2 after expiry", issued)
	}
	valid = "revoked"
	digest() // the cached token is rejected: one fresh token
	if issued != 3 {
		t.Fatalf("%d tokens, want 3 after a rejection", issued)
	}
}

// The Docker Hub credentials go only to Docker Hub's token service, for a Docker Hub
// image: a registry named in a pod spec can't collect them with a realm that merely
// mentions docker.io.
func TestDockerHubCredentialsStayWithDockerHub(t *testing.T) {
	hub := Ref{Registry: "registry-1.docker.io", Repository: "library/php"}
	other := Ref{Registry: "evil.example:5000", Repository: "tenant/app"}
	for _, tc := range []struct {
		ref   Ref
		realm string
		want  bool
	}{
		{hub, "https://auth.docker.io/token", true},
		{hub, "http://auth.docker.io/token", false},
		{hub, "https://auth.docker.io.evil.example/token", false},
		{hub, "https://evil.example/docker.io/token", false},
		{hub, "https://auth.docker.io:8443/token", false},
		{other, "https://auth.docker.io/token", false},
		{other, "https://evil.example/auth.docker.io", false},
	} {
		u, err := url.Parse(tc.realm)
		if err != nil {
			t.Fatal(err)
		}
		if got := dockerHubAuth(tc.ref, u); got != tc.want {
			t.Errorf("%s with realm %s: %v, want %v", tc.ref.Registry, tc.realm, got, tc.want)
		}
	}

	// End to end: a registry whose realm mentions docker.io gets no credentials.
	var gotAuth bool
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/docker.io/token" {
			_, _, gotAuth = r.BasicAuth()
			w.Write([]byte(`{"token":"x"}`))
			return
		}
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("Www-Authenticate", `Bearer realm="`+srv.URL+`/docker.io/token"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Docker-Content-Digest", "sha256:feed")
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), Scheme: "http", Username: "me", Password: "dckr_pat_secret"}
	if _, err := c.Digest(context.Background(), Ref{Registry: strings.TrimPrefix(srv.URL, "http://"), Repository: "tenant/app", Tag: "1"}); err != nil {
		t.Fatal(err)
	}
	if gotAuth {
		t.Error("credentials sent to a registry that isn't Docker Hub")
	}
	// Outside tests, a realm must be https.
	c = &Client{HTTP: srv.Client(), Scheme: "https"}
	if _, _, err := c.token(context.Background(), `Bearer realm="http://auth.example/token"`, other, false); err == nil {
		t.Error("http realm accepted")
	}
}

func TestTokenLife(t *testing.T) {
	for raw, want := range map[string]time.Duration{
		`300`: 285 * time.Second, `"300"`: 285 * time.Second, `300.0`: 285 * time.Second, `1e3`: 985 * time.Second,
		`10`: 10 * time.Second, `-5`: 45 * time.Second, `0`: 45 * time.Second, `null`: 45 * time.Second, ``: 45 * time.Second,
		`"NaN"`: 45 * time.Second, `1e400`: 45 * time.Second, `99999999999999999999`: 3585 * time.Second,
	} {
		if got := tokenLife(json.RawMessage(raw)); got != want {
			t.Errorf("tokenLife(%s) = %s, want %s", raw, got, want)
		}
	}
}
