package registry

import (
	"strings"
	"testing"
)

// FuzzParseRef: references come from images.csv and from Syft metadata. ParseRef must
// never panic, an accepted reference must have a registry and a repository, and its
// string form must parse back to the same reference (String drops the tag when there
// is a digest).
func FuzzParseRef(f *testing.F) {
	for _, s := range []string{"php:8.4-apache", "ghcr.io/acme/app:1.2", "localhost:5000/app", "php@sha256:abc", "php:8.4@sha256:abc", "registry:php", ":", "@", "/:@", "php:", "a//b", "x/a:b/c", "docker.io/php"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParseRef(s)
		if err != nil {
			return
		}
		if r.Registry == "" || r.Repository == "" || strings.Contains(r.Repository, "@") {
			t.Fatalf("ParseRef(%q) = %+v", s, r)
		}
		back, err := ParseRef(r.String())
		if r.Digest != "" {
			r.Tag = ""
		}
		if err != nil || back != r {
			t.Fatalf("ParseRef(%q) = %+v, but %q parses to %+v (%v)", s, r, r.String(), back, err)
		}
	})
}

// FuzzParseChallenge: the WWW-Authenticate header comes from the registry.
func FuzzParseChallenge(f *testing.F) {
	f.Add(`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/php:pull"`)
	f.Add(`Bearer realm=",",x="`)
	f.Fuzz(func(t *testing.T, s string) {
		_ = parseChallenge(s)
	})
}
