package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yusufyildiz34/whichphp/internal/phpini"
	"github.com/yusufyildiz34/whichphp/internal/report"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

// writeReport writes a whichphp image report of php:<version>-apache with one libphp
// build, every CVE judged v, and returns its path. A report whose action is NO_PHP has
// no build.
func writeReport(t *testing.T, dir, name, version string, v verdict.Verdict, action verdict.Action, upload string) string {
	t.Helper()
	cves := map[string]verdict.CVEResult{
		"CVE-2026-109618": {Verdict: v, Why: "test"},
		"CVE-2026-109619": {Verdict: v, Why: "test"},
	}
	rep := verdict.Report{
		Tool: "whichphp", Version: "test",
		Image: verdict.Image{Input: "php:" + version + "-apache", SourceType: "image", Tags: []string{"php:" + version + "-apache"},
			ManifestDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222", Created: "2026-10-22T03:10:00Z"},
		PHP:      []verdict.PHP{{Name: "libphp", Version: version, Source: verdict.SourceUpstream, SAPI: "apache-module", CVEs: cves}},
		Verdicts: map[string]verdict.Verdict{"CVE-2026-109618": v, "CVE-2026-109619": v},
		Settings: map[string]phpini.Setting{phpini.UploadProgress: {Effective: upload}},
		Action:   action,
	}
	if action == verdict.ActionNoPHP {
		rep.PHP, rep.Verdicts, rep.Settings = nil, map[string]verdict.Verdict{}, nil
	}
	return writeJSON(t, dir, name, rep)
}

// writeJSON writes a report as whichphp image -o json does, and returns its path.
func writeJSON(t *testing.T, dir, name string, rep verdict.Report) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := report.JSON(f, rep); err != nil {
		t.Fatal(err)
	}
	return path
}

// imageReport writes the report "whichphp image -o json" gives for the pre-fix
// php:8.4.26-apache fixture, and returns its path.
func imageReport(t *testing.T, dir string) string {
	t.Helper()
	sbom, grype := fixture(t, "php:8.4.26-apache", []string{"php:8.4.26-apache"})
	path := filepath.Join(dir, "before.json")
	if code, _, stderr := runCLI("image", "--sbom", sbom, "--grype-json", grype, "-o", "json="+path); code != 1 {
		t.Fatalf("image: exit %d: %s", code, stderr)
	}
	return path
}

func TestDiffReportFiles(t *testing.T) {
	dir := t.TempDir()
	before := imageReport(t, dir)
	after := writeReport(t, dir, "after.json", "8.4.27", verdict.Fixed, verdict.ActionOK, "on")
	code, stdout, stderr := runCLI("diff", before, after)
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, want 0 (the after image is fixed); stderr: %s", code, stderr)
	}
	for _, want := range []string{
		"php:8.4.26-apache", "php:8.4.27-apache", "sha256:6985ff1ba36e…", "sha256:222222222222…",
		"2026-10-21T00:32:27Z", "2026-10-22T03:10:00Z",
		"  changed    libphp 8.4.26 → 8.4.27 (apache-module)\n    CVE-2026-109618, CVE-2026-109619: VULNERABLE → FIXED\n",
		"Result: Fixed by this change: ACTION NEEDED → OK (exit 0)\n",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, stdout)
		}
	}
	// The fixture's SBOM has no php.ini contents, so the setting isn't known before.
	if !strings.Contains(stdout, "session.upload_progress.enabled  unknown") {
		t.Errorf("upload progress row:\n%s", stdout)
	}
	// The after report comes from another version of whichphp than this one; the
	// before report, just written, doesn't.
	if !strings.Contains(stdout, "  - The after report was made by whichphp test, not by this whichphp "+version+"; its verdicts follow the rules of that version") ||
		strings.Contains(stdout, "The before report was made") {
		t.Errorf("version notes:\n%s", stdout)
	}

	// The other way round, it got worse, and the after image decides the exit code.
	code, stdout, _ = runCLI("diff", after, before)
	if code != 1 || !strings.Contains(stdout, "Result: Got worse: OK → ACTION NEEDED (exit 1)") {
		t.Errorf("reversed: exit %d\n%s", code, stdout)
	}
	code, stdout, _ = runCLI("diff", before, before)
	if code != 1 || !strings.Contains(stdout, "Result: No PHP change: ACTION NEEDED before and after (exit 1)") || !strings.Contains(stdout, "the same image") {
		t.Errorf("same report: exit %d\n%s", code, stdout)
	}
}

func TestDiffExitCodes(t *testing.T) {
	dir := t.TempDir()
	before := writeReport(t, dir, "before.json", "8.4.26", verdict.Vulnerable, verdict.ActionNeeded, "on")
	for _, c := range []struct {
		v      verdict.Verdict
		action verdict.Action
		exit   int
		result string
	}{
		{verdict.Fixed, verdict.ActionOK, 0, "Fixed by this change"},
		{verdict.Vulnerable, verdict.ActionNeeded, 1, "Still vulnerable"},
		{verdict.Unknown, verdict.ActionUnknown, 2, "Better, but not proven fixed"},
		{verdict.Fixed, verdict.ActionNoPHP, 0, "No PHP found in the after image, which isn't proof of a fix"},
	} {
		after := writeReport(t, dir, "after.json", "8.4.27", c.v, c.action, "on")
		// Flags may come after the arguments.
		code, stdout, stderr := runCLI("diff", before, after, "--max-db-age", "3")
		if code != c.exit || !strings.Contains(stdout, "Result: "+c.result+":") {
			t.Errorf("after %s: exit %d, want %d; stderr %q\n%s", c.action, code, c.exit, stderr, stdout)
		}
	}
}

func TestDiffJSON(t *testing.T) {
	dir := t.TempDir()
	before := writeReport(t, dir, "before.json", "8.4.26", verdict.Vulnerable, verdict.ActionNeeded, "on")
	after := writeReport(t, dir, "after.json", "8.4.27", verdict.Fixed, verdict.ActionOK, "off")
	code, stdout, stderr := runCLI("diff", "-o", "json", before, after)
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	var d struct {
		Tool, Version, Outcome, Summary string
		Action, UploadProgress          map[string]string
		PHP                             []struct{ Change, Match string }
	}
	if err := json.Unmarshal([]byte(stdout), &d); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if d.Tool != "whichphp" || d.Version != version || d.Outcome != "FIXED" || d.Summary != "Fixed by this change" ||
		d.Action["after"] != "OK" || d.UploadProgress["before"] != "on" || d.UploadProgress["after"] != "off" ||
		len(d.PHP) != 1 || d.PHP[0].Change != "changed" || d.PHP[0].Match != "name" {
		t.Errorf("%+v\n%s", d, stdout)
	}

	out := filepath.Join(dir, "diff.json")
	code, stdout, _ = runCLI("diff", before, after, "-o", "table", "-o", "json="+out)
	if code != 0 || !strings.Contains(stdout, "Result: Fixed by this change") {
		t.Errorf("table on stdout: exit %d\n%s", code, stdout)
	}
	if b, err := os.ReadFile(out); err != nil || !json.Valid(b) {
		t.Errorf("diff.json: %v", err)
	}
	assertNoTempFiles(t, dir)
}

func TestDiffFailOnMitigation(t *testing.T) {
	dir := t.TempDir()
	before := writeReport(t, dir, "before.json", "8.4.26", verdict.Vulnerable, verdict.ActionNeeded, "on")
	after := writeReport(t, dir, "after.json", "8.4.27", verdict.Fixed, verdict.ActionOK, "on")
	if code, stdout, _ := runCLI("diff", before, after, "--fail-on-mitigation"); code != 1 || !strings.Contains(stdout, "Still vulnerable") {
		t.Errorf("exit %d, want 1 with upload progress on\n%s", code, stdout)
	}
}

func TestDiffArguments(t *testing.T) {
	dir := t.TempDir()
	before := writeReport(t, dir, "before.json", "8.4.26", verdict.Vulnerable, verdict.ActionNeeded, "on")
	cluster := filepath.Join(dir, "cluster.json")
	if err := os.WriteFile(cluster, []byte(`{"tool":"whichphp","context":"lab","action":"OK","workloads":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"no arguments":             {},
		"one argument":             {before},
		"three arguments":          {before, before, before},
		"a flag-like argument":     {"--", before, "--config=/etc/passwd"},
		"an image format":          {before, before, "-o", "sarif"},
		"two outputs to stdout":    {before, before, "-o", "table", "-o", "json"},
		"output over an input":     {before, before, "-o", "json=" + before},
		"a cluster report":         {before, cluster},
		"a missing report":         {before, filepath.Join(dir, "after.json")},
		"an image-only flag":       {before, before, "--sbom", "x.json"},
		"an unknown output format": {before, before, "-o", "xml"},
	} {
		code, stdout, stderr := runCLI(append([]string{"diff"}, args...)...)
		if code != 3 || stdout != "" || stderr == "" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, code, stdout, stderr)
		}
	}
	if _, _, stderr := runCLI("diff", before, cluster); !strings.Contains(stderr, "after: ") || !strings.Contains(stderr, "isn't a whichphp image report") {
		t.Errorf("the error should name the argument and say why: %s", stderr)
	}
	if b, _ := os.ReadFile(before); !json.Valid(b) {
		t.Error("the before report was overwritten")
	}

	// An output that is a symlink to an input is the input: it must be neither
	// emptied before the input is read nor replaced after.
	latest := filepath.Join(dir, "latest.json")
	if err := os.Symlink(before, latest); err != nil {
		t.Skip("symlinks not supported:", err)
	}
	if code, stdout, stderr := runCLI("diff", before, before, "-o", "json="+latest); code != 3 || stdout != "" || !strings.Contains(stderr, "is used twice") {
		t.Errorf("output through a symlink to an input: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if b, _ := os.ReadFile(before); !json.Valid(b) || !strings.Contains(string(b), `"php"`) {
		t.Error("the before report was overwritten through a symlink")
	}

	// So is an archive given with its scheme.
	t.Chdir(dir)
	// Should the run get past its outputs, it finds no tools to run.
	t.Setenv("WHICHPHP_SYFT", filepath.Join(dir, "no-such-syft"))
	t.Setenv("WHICHPHP_GRYPE", filepath.Join(dir, "no-such-grype"))
	if err := os.WriteFile("old.tar", []byte("app/"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"docker-archive:old.tar", "oci-dir:old.tar", "dir:old.tar"} {
		if code, stdout, stderr := runCLI("diff", source, before, "-o", "json=old.tar"); code != 3 || stdout != "" || !strings.Contains(stderr, "is used twice") {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", source, code, stdout, stderr)
		}
	}
	if b, _ := os.ReadFile("old.tar"); string(b) != "app/" {
		t.Errorf("the archive was overwritten: %q", b)
	}
}

// TestDiffScansOtherArguments: an argument that isn't a report file goes to the same
// scan as whichphp image. Syft is replaced by a path that doesn't exist, so the scan
// fails at once; nothing is run.
func TestDiffScansOtherArguments(t *testing.T) {
	dir := t.TempDir()
	before := writeReport(t, dir, "before.json", "8.4.26", verdict.Vulnerable, verdict.ActionNeeded, "on")
	archive := filepath.Join(dir, "app.tar")
	if err := os.WriteFile(archive, []byte("app/\x00\x00\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WHICHPHP_SYFT", filepath.Join(dir, "no-such-syft"))
	for _, arg := range []string{archive, "docker-archive:" + archive} {
		code, stdout, stderr := runCLI("diff", before, arg, "--no-grype")
		if code != 3 || stdout != "" || !strings.Contains(stderr, "after: syft failed") {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", arg, code, stdout, stderr)
		}
	}
}

func TestDiffUsage(t *testing.T) {
	code, _, stderr := runCLI("diff", "-h")
	if code != 0 {
		t.Errorf("exit %d", code)
	}
	for _, want := range []string{"whichphp diff <before> <after>", "whichphp image\n    -o json=<file>", "is read, not scanned again", "Exit codes come from the after image", "-fail-on-mitigation"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("usage lacks %q:\n%s", want, stderr)
		}
	}
	if _, out, _ := runCLI("help"); !strings.Contains(out, "whichphp diff <before> <after> [flags]") {
		t.Errorf("the main usage should list diff:\n%s", out)
	}
}

// A fix that rests on an unconfirmed distro backport isn't called fixed, and the output
// says why.
func TestDiffUnconfirmedBackport(t *testing.T) {
	dir := t.TempDir()
	before := writeReport(t, dir, "before.json", "8.4.26", verdict.Vulnerable, verdict.ActionNeeded, "on")
	unconfirmed := verdict.CVEResult{Verdict: verdict.FixedByDistroBackport, Why: "test", Unconfirmed: true}
	after := writeJSON(t, dir, "after.json", verdict.Report{
		Tool: "whichphp", Version: version, Image: verdict.Image{Input: "app:2", SourceType: "image", Tags: []string{"app:2"}},
		PHP: []verdict.PHP{{Name: "libapache2-mod-php8.3", Version: "8.3.6-0ubuntu0.24.04.13", Source: verdict.SourceDistro, SAPI: "apache-module",
			CVEs: map[string]verdict.CVEResult{"CVE-2026-109618": unconfirmed, "CVE-2026-109619": unconfirmed}}},
		Verdicts: map[string]verdict.Verdict{"CVE-2026-109618": verdict.FixedByDistroBackport, "CVE-2026-109619": verdict.FixedByDistroBackport},
		Action:   verdict.ActionOK,
	})
	code, stdout, stderr := runCLI("diff", before, after)
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	for _, want := range []string{"FIXED_BY_DISTRO_BACKPORT (unconfirmed)", "Result: Better, but not proven fixed: ACTION NEEDED → OK (exit 0)"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, stdout)
		}
	}
	_, stdout, _ = runCLI("diff", "-o", "json", before, after)
	var d struct {
		Outcome  string
		Verdicts map[string]struct{ Unconfirmed struct{ After bool } }
	}
	if err := json.Unmarshal([]byte(stdout), &d); err != nil || d.Outcome != "IMPROVED" || !d.Verdicts["CVE-2026-109618"].Unconfirmed.After {
		t.Errorf("%v: %+v\n%s", err, d, stdout)
	}
}

// A report whose action contradicts its contents is refused, so it can't decide the
// result or the exit code.
func TestDiffRejectsContradictoryReports(t *testing.T) {
	dir := t.TempDir()
	before := writeReport(t, dir, "before.json", "8.4.26", verdict.Vulnerable, verdict.ActionNeeded, "on")
	for name, action := range map[string]verdict.Action{"ok.json": verdict.ActionOK, "nophp.json": verdict.ActionNoPHP} {
		rep := verdict.Report{Tool: "whichphp", Version: version, Image: verdict.Image{Input: "app:2"},
			PHP:      []verdict.PHP{{Name: "php", Version: "8.4.26", SAPI: "cli", CVEs: map[string]verdict.CVEResult{"CVE-2026-109618": {Verdict: verdict.Vulnerable}}}},
			Verdicts: map[string]verdict.Verdict{"CVE-2026-109618": verdict.Vulnerable}, Action: action}
		after := writeJSON(t, dir, name, rep)
		code, stdout, stderr := runCLI("diff", before, after)
		if code != 3 || stdout != "" || !strings.Contains(stderr, "contradicts") {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, code, stdout, stderr)
		}
	}
}
