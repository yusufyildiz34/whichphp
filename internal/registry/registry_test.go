package registry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
