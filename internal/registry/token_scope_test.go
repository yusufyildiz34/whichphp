package registry

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// rt routes requests in-process by host; nothing leaves the machine.
type rt map[string]http.HandlerFunc

func (m rt) RoundTrip(r *http.Request) (*http.Response, error) {
	h, ok := m[r.URL.Host]
	if !ok {
		return &http.Response{StatusCode: 599, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}, Request: r}, nil
	}
	rec := httptest.NewRecorder()
	h(rec, r)
	resp := rec.Result()
	resp.Request = r
	return resp, nil
}

// A token made with the Docker Hub credentials is cached for Docker Hub only: another
// registry whose challenge names the same realm, service and scope doesn't get it.
func TestCachedHubTokenStaysWithDockerHub(t *testing.T) {
	const challenge = `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:victimorg/private:pull"`
	var evilSaw []string
	routes := rt{
		"auth.docker.io": func(w http.ResponseWriter, r *http.Request) {
			if u, p, ok := r.BasicAuth(); ok && u == "me" && p == "dckr_pat_secret" {
				io.WriteString(w, `{"token":"TOKEN-MINTED-WITH-USER-CREDS","expires_in":300}`)
				return
			}
			io.WriteString(w, `{"token":"anonymous","expires_in":300}`)
		},
		"registry-1.docker.io": func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "Bearer TOKEN-MINTED-WITH-USER-CREDS" {
				w.Header().Set("Docker-Content-Digest", "sha256:private")
				return
			}
			w.Header().Set("Www-Authenticate", challenge)
			w.WriteHeader(http.StatusUnauthorized)
		},
		"evil.example": func(w http.ResponseWriter, r *http.Request) {
			evilSaw = append(evilSaw, r.Header.Get("Authorization"))
			if r.Header.Get("Authorization") == "" {
				w.Header().Set("Www-Authenticate", challenge)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Docker-Content-Digest", "sha256:whatever")
		},
	}
	c := &Client{HTTP: &http.Client{Transport: routes}, Username: "me", Password: "dckr_pat_secret"}
	hub, _ := ParseRef("victimorg/private:1")
	if d, err := c.Digest(context.Background(), hub); err != nil || d != "sha256:private" {
		t.Fatalf("hub: %q %v", d, err)
	}
	evil, _ := ParseRef("evil.example/x:1")
	c.Digest(context.Background(), evil)
	for _, a := range evilSaw {
		if strings.Contains(a, "USER-CREDS") {
			t.Errorf("evil.example received %q (a token minted with DOCKERHUB credentials)", a)
		}
	}
}
