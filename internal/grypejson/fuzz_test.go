package grypejson

import "testing"

var tracked = []string{"CVE-2026-109618", "CVE-2026-109619"}

// FuzzParseMatches: Grype's JSON can be handed to whichphp with --grype-json, so it is
// untrusted input. Parsing must never panic, and every hit must be for a tracked CVE.
func FuzzParseMatches(f *testing.F) {
	f.Add([]byte(`{"matches":[{"vulnerability":{"id":"GHSA-x","fix":{"versions":["8.4.27"],"state":"fixed"}},"relatedVulnerabilities":[{"id":"CVE-2026-109618"}],"matchDetails":[{"type":"cpe-match"}],"artifact":{"name":"php-cli","version":"8.4.26"}}]}`))
	f.Add([]byte(`{"matches":[{"vulnerability":{"id":"CVE-2026-109619","fix":{"versions":"x"}},"artifact":{}}]}`))
	f.Add([]byte(`{"matches":null}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		hits, err := ParseMatches(b, tracked)
		if err != nil {
			return
		}
		for k, hs := range hits {
			for _, h := range hs {
				if h.CVE != tracked[0] && h.CVE != tracked[1] {
					t.Fatalf("%v: hit for untracked %q", k, h.CVE)
				}
			}
		}
	})
}

// FuzzParseSearch and FuzzParseStatus: Grype's search and status output is read from
// a subprocess, so a malformed or hostile database must not crash whichphp.
func FuzzParseSearch(f *testing.F) {
	f.Add([]byte(`[{"vulnerability":{"id":"CVE-2026-109618"},"packages":[{"os":{"name":"ubuntu","version":"24.04"},"package":{"name":"php8.3"},"detail":{"ranges":[{"fix":{"version":"8.3.6-0ubuntu0.24.04.13","state":"fixed"}}]}}]}]`))
	f.Add([]byte(`[{"packages":[{"detail":{"ranges":[{"fix":[]}]}}]}]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseSearch(b)
	})
}

func FuzzParseStatus(f *testing.F) {
	f.Add([]byte(`{"built":"2026-10-31T00:00:00Z","schemaVersion":"v6","valid":true}`))
	f.Add([]byte(`{"built":1}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		// The caller reads the status right after a nil error, so it must never be nil.
		if s, err := ParseStatus(b); err == nil && s == nil {
			t.Fatalf("nil status without an error for %q", b)
		}
	})
}
