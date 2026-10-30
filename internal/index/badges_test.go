package index

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBadgesCountTagsNotPlatforms(t *testing.T) {
	php := []PHP{{Name: "php-cli", Version: "8.4.26"}}
	idx := &Index{
		Generated:    "2026-10-31T05:40:00Z",
		GrypeDBBuilt: "2026-10-31T04:10:00Z",
		Entries: []Entry{
			// Vulnerable on one platform only: counts once.
			{Ref: "a:1", Platform: "linux/amd64", PHP: php, UploadProgress: "on", Verdicts: map[string]string{"CVE-2026-109618": "VULNERABLE"}},
			{Ref: "a:1", Platform: "linux/arm64", PHP: php, UploadProgress: "on", Verdicts: map[string]string{"CVE-2026-109618": "FIXED"}},
			{Ref: "b:1", Platform: "linux/amd64", PHP: php, UploadProgress: "off-in-fpm-pool", Verdicts: map[string]string{"CVE-2026-109618": "FIXED_BY_DISTRO_BACKPORT"}},
			{Ref: "b:1", Platform: "linux/arm64", Action: noBuildAction},
			{Ref: "c:1", Platform: "linux/amd64", Verdicts: map[string]string{"CVE-2026-109618": "VULNERABLE_EOL"}, PHP: php, UploadProgress: "on"},
			// Never scanned successfully: tracked, but not part of "of N".
			{Ref: "d:1", Platform: "linux/amd64", Error: "rate limited"},
			// Control tags are left out entirely.
			{Ref: "php:8.4.26-apache", Platform: "linux/amd64", Kind: demoKind, PHP: php, Verdicts: map[string]string{"CVE-2026-109618": "VULNERABLE"}},
		},
	}
	b := Badges(idx)
	want := map[string]string{
		"tracked.json":         "4",
		"vulnerable.json":      "2 of 3",
		"upload-progress.json": "75% of builds",
		"updated.json":         "2026-10-31",
		"grype-db.json":        "2026-10-31",
	}
	if len(b) != len(want) {
		t.Fatalf("got %d badges, want %d", len(b), len(want))
	}
	for name, msg := range want {
		if b[name].Message != msg || b[name].SchemaVersion != 1 {
			t.Errorf("%s: got %+v, want message %q", name, b[name], msg)
		}
	}
}

func TestBadgesWithNothingVulnerable(t *testing.T) {
	b := Badges(&Index{Entries: []Entry{{Ref: "a:1", Platform: "linux/amd64", Verdicts: map[string]string{"CVE-2026-109618": "FIXED"}}}})
	if b["vulnerable.json"].Message != "none" || b["upload-progress.json"].Message != "no data" || b["updated.json"].Message != "unknown" {
		t.Fatalf("got %+v", b)
	}
}

func TestSaveBadges(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "badges")
	if err := SaveBadges(dir, Badges(&Index{})); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "tracked.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got Badge
	if err := json.Unmarshal(raw, &got); err != nil || got.Label != "images tracked" || got.Message != "0" {
		t.Fatalf("got %+v, %v", got, err)
	}
}
