package grypejson

import "testing"

func TestParseMatchesUsesRelatedIDs(t *testing.T) {
	b := []byte(`{"matches":[
	 {"vulnerability":{"id":"GHSA-xxxx","namespace":"github:language:php","fix":{"versions":["8.4.27"],"state":"fixed"}},
	  "relatedVulnerabilities":[{"id":"CVE-2026-109618"}],
	  "matchDetails":[{"type":"cpe-match"}],
	  "artifact":{"name":"php-cli","version":"8.4.26"}},
	 {"vulnerability":{"id":"CVE-2099-0001"},"artifact":{"name":"openssl","version":"3.0.0"}}]}`)
	hits, err := ParseMatches(b, []string{"CVE-2026-109618", "CVE-2026-109619"})
	if err != nil {
		t.Fatal(err)
	}
	h := hits[Key{"php-cli", "8.4.26"}]
	if len(h) != 1 || h[0].CVE != "CVE-2026-109618" || h[0].FixVersions[0] != "8.4.27" || h[0].MatchedBy != "cpe-match" {
		t.Fatalf("got %+v", hits)
	}
	if _, ok := hits[Key{"openssl", "3.0.0"}]; ok {
		t.Fatal("unrelated CVE must be ignored")
	}
}

func TestParseSearchLoose(t *testing.T) {
	b := []byte(`[{"vulnerability":{"id":"CVE-2026-109618"},"packages":[
	  {"os":{"name":"ubuntu","version":"24.04"},"package":{"name":"php8.3","ecosystem":"deb"},"namespace":"ubuntu:distro:ubuntu:24.04",
	   "detail":{"ranges":[{"version":{"constraint":"< 8.3.6-0ubuntu0.24.04.13"},"fix":{"version":"8.3.6-0ubuntu0.24.04.13","state":"fixed"}}]}},
	  {"os":{"name":"debian","version":"12"},"package":{"name":"php8.2"},"detail":{}}]}]`)
	got, err := ParseSearch(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].OS != "ubuntu" || got[0].FixVersion != "8.3.6-0ubuntu0.24.04.13" || got[1].Package != "php8.2" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseStatus(t *testing.T) {
	s, err := ParseStatus([]byte(`{"schemaVersion":"v6.1.10","built":"2026-10-30T06:23:28Z","path":"/x"}`))
	if err != nil || s.Built.IsZero() {
		t.Fatalf("got %+v, %v", s, err)
	}
}
