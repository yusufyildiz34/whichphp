package index

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yusufyildiz34/whichphp/internal/registry"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

type fake struct {
	digests map[string]string
	reports map[string]verdict.Report // key ref|platform
	errs    map[string]error
	scans   []string
}

func (f *fake) resolve(_ context.Context, ref string) (string, error) {
	if err, ok := f.errs["resolve|"+ref]; ok {
		return "", err
	}
	return f.digests[ref], nil
}

func (f *fake) scan(_ context.Context, ref, platform string) (verdict.Report, error) {
	k := ref + "|" + platform
	f.scans = append(f.scans, k)
	if err, ok := f.errs[k]; ok {
		return verdict.Report{}, err
	}
	return f.reports[k], nil
}

func report(digest string, action verdict.Action, v verdict.Verdict) verdict.Report {
	r := verdict.Report{Action: action, Verdicts: map[string]verdict.Verdict{"CVE-2026-109618": v, "CVE-2026-109619": v}}
	r.Image.ManifestDigest = digest
	r.PHP = []verdict.PHP{{Name: "php-cli", Version: "8.4.26", Source: verdict.SourceUpstream, SAPI: "cli"}}
	return r
}

func clock(t string) func() time.Time {
	tt, _ := time.Parse(time.RFC3339, t)
	return func() time.Time { return tt }
}

var amd = []string{"linux/amd64"}

func TestFirstRunScansEverything(t *testing.T) {
	f := &fake{
		digests: map[string]string{"php:8.4-apache": "sha256:idx1"},
		reports: map[string]verdict.Report{"php:8.4-apache|linux/amd64": report("sha256:img1", verdict.ActionNeeded, verdict.Vulnerable)},
	}
	idx, changes := Update(context.Background(), []Image{{Ref: "php:8.4-apache", Kind: "pinned"}}, nil, f.resolve, f.scan,
		Options{Platforms: amd, RescanAfter: 7 * 24 * time.Hour, Now: clock("2026-10-30T00:00:00Z")})
	if len(idx.Entries) != 1 || idx.Entries[0].Action != "ACTION_NEEDED" || idx.Entries[0].TagDigest != "sha256:idx1" || len(changes) != 1 {
		t.Fatalf("got %+v / %+v", idx.Entries, changes)
	}
}

func TestUnchangedDigestIsNotRescanned(t *testing.T) {
	prev := &Index{Schema: SchemaVersion, Entries: []Entry{{Ref: "php:8.4-apache", Platform: "linux/amd64", TagDigest: "sha256:idx1",
		ImageDigest: "sha256:img1", ScannedAt: "2026-10-29T00:00:00Z", Action: "OK"}}}
	f := &fake{digests: map[string]string{"php:8.4-apache": "sha256:idx1"}}
	idx, changes := Update(context.Background(), []Image{{Ref: "php:8.4-apache"}}, prev, f.resolve, f.scan,
		Options{Platforms: amd, RescanAfter: 7 * 24 * time.Hour, Now: clock("2026-10-30T00:00:00Z")})
	if len(f.scans) != 0 || len(changes) != 0 || idx.Entries[0].CheckedAt != "2026-10-30T00:00:00Z" || idx.Entries[0].ScannedAt != "2026-10-29T00:00:00Z" {
		t.Fatalf("scans %v, changes %v, entry %+v", f.scans, changes, idx.Entries[0])
	}
}

func TestStaleEntryIsRescanned(t *testing.T) {
	prev := &Index{Schema: SchemaVersion, Entries: []Entry{{Ref: "php:8.4-apache", Platform: "linux/amd64", TagDigest: "sha256:idx1",
		ImageDigest: "sha256:img1", ScannedAt: "2026-10-20T00:00:00Z", Action: "OK"}}}
	f := &fake{digests: map[string]string{"php:8.4-apache": "sha256:idx1"},
		reports: map[string]verdict.Report{"php:8.4-apache|linux/amd64": report("sha256:img1", verdict.ActionOK, verdict.Fixed)}}
	Update(context.Background(), []Image{{Ref: "php:8.4-apache"}}, prev, f.resolve, f.scan,
		Options{Platforms: amd, RescanAfter: 7 * 24 * time.Hour, Now: clock("2026-10-30T00:00:00Z")})
	if len(f.scans) != 1 {
		t.Fatalf("expected a rescan, got %v", f.scans)
	}
}

func TestFirstFixedIsRecorded(t *testing.T) {
	prev := &Index{Schema: SchemaVersion, Entries: []Entry{{Ref: "php:8.4-apache", Platform: "linux/amd64", TagDigest: "sha256:idx1",
		ImageDigest: "sha256:img1", ScannedAt: "2026-10-20T00:00:00Z", Action: "ACTION_NEEDED"}}}
	f := &fake{digests: map[string]string{"php:8.4-apache": "sha256:idx2"},
		reports: map[string]verdict.Report{"php:8.4-apache|linux/amd64": report("sha256:img2", verdict.ActionOK, verdict.Fixed)}}
	idx, changes := Update(context.Background(), []Image{{Ref: "php:8.4-apache"}}, prev, f.resolve, f.scan,
		Options{Platforms: amd, Now: clock("2026-10-22T00:00:00Z")})
	e := idx.Entries[0]
	if e.FirstFixedDigest != "sha256:img2" || e.FirstFixedSeen != "2026-10-22T00:00:00Z" || len(changes) != 1 || changes[0].FromAction != "ACTION_NEEDED" {
		t.Fatalf("got %+v / %+v", e, changes)
	}
	// It stays recorded on later runs.
	f.digests["php:8.4-apache"] = "sha256:idx3"
	f.reports["php:8.4-apache|linux/amd64"] = report("sha256:img3", verdict.ActionOK, verdict.Fixed)
	idx2, _ := Update(context.Background(), []Image{{Ref: "php:8.4-apache"}}, idx, f.resolve, f.scan,
		Options{Platforms: amd, Now: clock("2026-10-25T00:00:00Z")})
	if idx2.Entries[0].FirstFixedDigest != "sha256:img2" {
		t.Fatalf("first fixed digest lost: %+v", idx2.Entries[0])
	}
}

func TestMissingPlatformIsCachedNotRetried(t *testing.T) {
	f := &fake{digests: map[string]string{"app:1": "sha256:idx"},
		errs: map[string]error{"app:1|linux/arm64": errors.New("no child with platform linux/arm64 in index")}}
	idx, _ := Update(context.Background(), []Image{{Ref: "app:1"}}, nil, f.resolve, f.scan,
		Options{Platforms: []string{"linux/arm64"}, RescanAfter: 7 * 24 * time.Hour, Now: clock("2026-10-30T00:00:00Z")})
	if e := idx.Entries[0]; e.Action != "NO_BUILD" || e.Error != "" {
		t.Fatalf("got %+v", e)
	}
	f.scans = nil
	Update(context.Background(), []Image{{Ref: "app:1"}}, idx, f.resolve, f.scan,
		Options{Platforms: []string{"linux/arm64"}, RescanAfter: 7 * 24 * time.Hour, Now: clock("2026-10-31T00:00:00Z")})
	if len(f.scans) != 0 {
		t.Fatalf("missing platform rescanned: %v", f.scans)
	}
}

func TestTransientErrorKeepsGoodData(t *testing.T) {
	prev := &Index{Schema: SchemaVersion, Entries: []Entry{{Ref: "php:8.4-apache", Platform: "linux/amd64", TagDigest: "sha256:idx1",
		ImageDigest: "sha256:img1", ScannedAt: "2026-10-01T00:00:00Z", Action: "OK"}}}
	f := &fake{digests: map[string]string{"php:8.4-apache": "sha256:idx1"},
		errs: map[string]error{"php:8.4-apache|linux/amd64": errors.New("connection reset by peer")}}
	idx, _ := Update(context.Background(), []Image{{Ref: "php:8.4-apache"}}, prev, f.resolve, f.scan,
		Options{Platforms: amd, RescanAfter: 7 * 24 * time.Hour, Now: clock("2026-10-30T00:00:00Z")})
	if e := idx.Entries[0]; e.Action != "OK" || e.Error != "" || e.ImageDigest != "sha256:img1" {
		t.Fatalf("got %+v", e)
	}
}

func TestRateLimitStopsChecking(t *testing.T) {
	prev := &Index{Schema: SchemaVersion, Entries: []Entry{{Ref: "b:1", Platform: "linux/amd64", TagDigest: "sha256:b", Action: "OK", ScannedAt: "2026-10-29T00:00:00Z"}}}
	f := &fake{digests: map[string]string{"b:1": "sha256:changed"},
		errs: map[string]error{"resolve|a:1": fmt.Errorf("x: %w", registry.ErrRateLimited)}}
	idx, _ := Update(context.Background(), []Image{{Ref: "a:1"}, {Ref: "b:1"}}, prev, f.resolve, f.scan,
		Options{Platforms: amd, Now: clock("2026-10-30T00:00:00Z")})
	if len(f.scans) != 0 || len(idx.Entries) != 1 || idx.Entries[0].TagDigest != "sha256:b" || len(idx.Notes) != 1 {
		t.Fatalf("scans %v, entries %+v, notes %v", f.scans, idx.Entries, idx.Notes)
	}
}

func TestMaxScansPrioritizesChangedTags(t *testing.T) {
	prev := &Index{Schema: SchemaVersion, Entries: []Entry{
		{Ref: "old:1", Platform: "linux/amd64", TagDigest: "sha256:o", Action: "OK", ScannedAt: "2026-10-01T00:00:00Z"},
		{Ref: "moved:1", Platform: "linux/amd64", TagDigest: "sha256:m1", Action: "ACTION_NEEDED", ScannedAt: "2026-10-29T00:00:00Z"},
	}}
	f := &fake{digests: map[string]string{"old:1": "sha256:o", "moved:1": "sha256:m2", "new:1": "sha256:n"},
		reports: map[string]verdict.Report{}}
	Update(context.Background(), []Image{{Ref: "old:1"}, {Ref: "new:1"}, {Ref: "moved:1"}}, prev, f.resolve, f.scan,
		Options{Platforms: amd, RescanAfter: 7 * 24 * time.Hour, MaxScans: 2, Now: clock("2026-10-30T00:00:00Z")})
	if len(f.scans) != 2 || f.scans[0] != "moved:1|linux/amd64" || f.scans[1] != "new:1|linux/amd64" {
		t.Fatalf("scan order %v", f.scans)
	}
}

func TestLoadImagesAndRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "images.csv")
	os.WriteFile(p, []byte("ref,kind,owner,note\n# comment\nphp:8.4-apache,pinned,php-official,\nphp:8.4-apache,pinned,php-official,dup\nwordpress:latest,latest,app-official,\"a, b\"\n"), 0o644)
	imgs, err := LoadImages(p)
	if err != nil || len(imgs) != 2 || imgs[1].Note != "a, b" {
		t.Fatalf("got %+v, %v", imgs, err)
	}
	ip := filepath.Join(dir, "index.json")
	if err := Save(ip, &Index{Schema: SchemaVersion, Entries: []Entry{{Ref: "x", Platform: "linux/amd64"}}}); err != nil {
		t.Fatal(err)
	}
	got, err := Load(ip)
	if err != nil || len(got.Entries) != 1 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if empty, err := Load(filepath.Join(dir, "missing.json")); err != nil || len(empty.Entries) != 0 {
		t.Fatalf("missing file: %+v, %v", empty, err)
	}
}

func TestTrackedImageListParses(t *testing.T) {
	imgs, err := LoadImages(filepath.Join("..", "..", "index", "images.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if len(imgs) < 50 {
		t.Fatalf("only %d images parsed", len(imgs))
	}
	for _, img := range imgs {
		if _, err := registry.ParseRef(img.Ref); err != nil {
			t.Errorf("%s: %v", img.Ref, err)
		}
		switch img.Kind {
		case "latest", "pinned", "demo":
		default:
			t.Errorf("%s: unknown kind %q", img.Ref, img.Kind)
		}
	}
}

func TestNotesRefreshWithoutRescan(t *testing.T) {
	prev := &Index{Schema: SchemaVersion, Entries: []Entry{{Ref: "joomla:4-apache", Platform: "linux/amd64", TagDigest: "sha256:j",
		ScannedAt: "2026-10-30T00:00:00Z", Action: "ACTION_NEEDED"}}}
	f := &fake{digests: map[string]string{"joomla:4-apache": "sha256:j"}}
	idx, _ := Update(context.Background(), []Image{{Ref: "joomla:4-apache", Kind: "pinned", Note: "Joomla 4 is end-of-life"}}, prev, f.resolve, f.scan,
		Options{Platforms: amd, RescanAfter: 7 * 24 * time.Hour, Now: clock("2026-10-31T00:00:00Z")})
	if len(f.scans) != 0 || idx.Entries[0].Note != "Joomla 4 is end-of-life" || idx.Entries[0].Kind != "pinned" {
		t.Fatalf("scans %v, entry %+v", f.scans, idx.Entries[0])
	}
}
