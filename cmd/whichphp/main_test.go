package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture writes a small Syft SBOM of a pre-fix php:8.4.26-apache image and an empty
// Grype result, and returns their paths.
func fixture(t *testing.T, input string, tags []string) (sbom, grype string) {
	t.Helper()
	dir := t.TempDir()
	cfg, _ := json.Marshal(map[string]any{"created": "2026-10-21T00:32:27Z", "config": map[string]any{"Cmd": []string{"apache2-foreground"}}})
	md, _ := json.Marshal(map[string]any{
		"userInput": input, "tags": tags, "architecture": "amd64", "config": cfg,
		"manifestDigest": "sha256:6985ff1ba36e5fda4a3257bef73c30b04ba657c29cf9cbaafc3f4d4ea0268a51",
	})
	doc := map[string]any{
		"descriptor": map[string]string{"name": "syft", "version": "1.55.0"},
		"distro":     map[string]string{"id": "debian", "versionID": "13"},
		"source":     map[string]any{"type": "image", "metadata": json.RawMessage(md)},
		"artifacts": []map[string]any{{
			"name": "libphp", "version": "8.4.26", "type": "binary", "purl": "pkg:generic/php@8.4.26",
			"cpes":      []map[string]string{{"cpe": "cpe:2.3:a:php:php:8.4.26:*:*:*:*:*:*:*"}},
			"locations": []map[string]string{{"path": "/usr/lib/apache2/modules/libphp.so"}},
		}},
	}
	b, _ := json.Marshal(doc)
	sbom, grype = filepath.Join(dir, "sbom.json"), filepath.Join(dir, "grype.json")
	if err := os.WriteFile(sbom, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(grype, []byte(`{"matches": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return sbom, grype
}

func runCLI(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestImageWritesEveryFormat(t *testing.T) {
	sbom, grype := fixture(t, "php:8.4.26-apache", []string{"php:8.4.26-apache"})
	dir := t.TempDir()
	code, stdout, stderr := runCLI("image", "--sbom", sbom, "--grype-json", grype, "-o", "table",
		"-o", "json="+filepath.Join(dir, "r.json"), "-o", "sarif="+filepath.Join(dir, "r.sarif"),
		"-o", "openvex="+filepath.Join(dir, "r.vex.json"), "--vex-author", "Acme",
		"-o", "cyclonedx="+filepath.Join(dir, "r.cdx.json"))
	if code != 1 {
		t.Fatalf("exit %d, want 1 (action needed); stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "ACTION NEEDED") || !strings.Contains(stdout, "Image:   php:8.4.26-apache") {
		t.Errorf("table:\n%s", stdout)
	}
	for _, name := range []string{"r.json", "r.sarif", "r.vex.json", "r.cdx.json"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !json.Valid(b) {
			t.Errorf("%s: %v, valid JSON %v", name, err, json.Valid(b))
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "r.vex.json")); !strings.Contains(string(b), `"author": "Acme"`) {
		t.Error("--vex-author not used")
	}
	assertNoTempFiles(t, dir)
}

func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("left a temporary file: %s", e.Name())
		}
	}
}

func TestOutputMistakesFailBeforeScanning(t *testing.T) {
	sbom, grype := fixture(t, "php:8.4.26-apache", []string{"php:8.4.26-apache"})
	dir := t.TempDir()
	out := filepath.Join(dir, "r.json")
	cases := map[string][]string{
		"unknown format":      {"-o", "xml"},
		"empty file name":     {"-o", "sarif="},
		"two to stdout":       {"-o", "table", "-o", "json"},
		"same file twice":     {"-o", "json=" + out, "-o", "sarif=" + out},
		"overwrites the SBOM": {"-o", "json=" + sbom},
		"missing directory":   {"-o", "sarif=" + filepath.Join(dir, "no", "such", "dir", "r.sarif")},
		"a directory":         {"-o", "sarif=" + dir},
	}
	for name, extra := range cases {
		args := append([]string{"image", "--sbom", sbom, "--grype-json", grype}, extra...)
		code, stdout, stderr := runCLI(args...)
		if code != 3 || stdout != "" || stderr == "" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, code, stdout, stderr)
		}
	}
	if b, _ := os.ReadFile(sbom); !json.Valid(b) {
		t.Error("the SBOM was overwritten")
	}
	assertNoTempFiles(t, dir)
}

func TestFailedOutputLeavesNoFiles(t *testing.T) {
	// An archive with no tag: OpenVEX can't name the product and fails, and the JSON
	// written before it must not be left behind either.
	sbom, grype := fixture(t, "/tmp/build/app.tar", nil)
	dir := t.TempDir()
	js, vex := filepath.Join(dir, "r.json"), filepath.Join(dir, "r.vex.json")
	code, stdout, stderr := runCLI("image", "--sbom", sbom, "--grype-json", grype, "-o", "json="+js, "-o", "openvex="+vex, "-o", "table")
	if code != 3 || stdout != "" || !strings.Contains(stderr, "OpenVEX") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	for _, f := range []string{js, vex} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("%s: a failed run must leave no output files", filepath.Base(f))
		}
	}
	assertNoTempFiles(t, dir)
}

func TestUnrelatedJSONIsNotAScan(t *testing.T) {
	// A wrong file given as the SBOM or the Grype output must fail, not pass as an
	// image with no PHP or a scan with no matches.
	sbom, grype := fixture(t, "php:8.4.26-apache", []string{"php:8.4.26-apache"})
	other := filepath.Join(t.TempDir(), "other.json")
	if err := os.WriteFile(other, []byte(`{"unrelated":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"image", "--sbom", other, "--no-grype", "-o", "json"},
		{"image", "--sbom", sbom, "--grype-json", other, "-o", "json"},
	} {
		if code, stdout, stderr := runCLI(args...); code != 3 || stdout != "" || stderr == "" {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, code, stdout, stderr)
		}
	}
	if code, _, stderr := runCLI("image", "--sbom", sbom, "--grype-json", grype, "-o", "json"); code != 1 {
		t.Fatalf("the real fixture must still scan: exit %d, stderr %q", code, stderr)
	}
}

func TestCycloneDXNeedsNoImageName(t *testing.T) {
	// Unlike OpenVEX, CycloneDX can describe an archive with no tag.
	sbom, grype := fixture(t, "/tmp/build/app.tar", nil)
	code, stdout, stderr := runCLI("image", "--sbom", sbom, "--grype-json", grype, "-o", "cyclonedx")
	if code != 1 || !json.Valid([]byte(stdout)) || !strings.Contains(stdout, `"name": "app.tar"`) || strings.Contains(stdout, "/tmp/build") {
		t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
	}
}

func TestOutputFilesAreReadableAndSymlinksKept(t *testing.T) {
	sbom, grype := fixture(t, "php:8.4.26-apache", []string{"php:8.4.26-apache"})
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks not supported:", err)
	}
	sarif := filepath.Join(dir, "r.sarif")
	if code, _, stderr := runCLI("image", "--sbom", sbom, "--grype-json", grype, "-o", "json="+link, "-o", "sarif="+sarif); code != 1 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced instead of written through")
	}
	if b, _ := os.ReadFile(target); !json.Valid(b) {
		t.Error("the symlink's target wasn't written")
	}
	if fi, err := os.Stat(sarif); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("new report files should be 0644: %v %v", fi.Mode(), err)
	}
}

// An output never truncates or replaces an input, under any name, and a symlinked
// output is replaced only once every output is complete.
func TestOutputsNeverOverwriteInputs(t *testing.T) {
	sbom, grype := fixture(t, "php:8.4.26-apache", []string{"php:8.4.26-apache"})
	dir := t.TempDir()
	symlink, hardlink := filepath.Join(dir, "latest.json"), filepath.Join(dir, "hard.json")
	if err := os.Symlink(sbom, symlink); err != nil {
		t.Skip("symlinks not supported:", err)
	}
	if err := os.Link(sbom, hardlink); err != nil {
		t.Skip("hard links not supported:", err)
	}
	for _, out := range []string{symlink, hardlink} {
		code, stdout, stderr := runCLI("image", "--sbom", sbom, "--grype-json", grype, "-o", "json="+out)
		if code != 3 || stdout != "" || !strings.Contains(stderr, "is used twice") {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", filepath.Base(out), code, stdout, stderr)
		}
	}
	if b, _ := os.ReadFile(sbom); !json.Valid(b) || !strings.Contains(string(b), `"artifacts"`) {
		t.Error("the SBOM was overwritten")
	}

	// An archive given with its scheme is an input too.
	t.Chdir(dir)
	// Should the run get past its outputs, it finds no tools to run.
	t.Setenv("WHICHPHP_SYFT", filepath.Join(dir, "no-such-syft"))
	t.Setenv("WHICHPHP_GRYPE", filepath.Join(dir, "no-such-grype"))
	if err := os.WriteFile("old.tar", []byte("app/"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"docker-archive:old.tar", "oci-archive:old.tar", "file:old.tar", "old.tar"} {
		code, stdout, stderr := runCLI("image", source, "-o", "json=old.tar")
		if code != 3 || stdout != "" || !strings.Contains(stderr, "is used twice") {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", source, code, stdout, stderr)
		}
	}
	if b, _ := os.ReadFile("old.tar"); string(b) != "app/" {
		t.Errorf("the archive was overwritten: %q", b)
	}

	// A run that fails leaves what a symlinked output points to as it was.
	archive, archiveGrype := fixture(t, "/tmp/build/app.tar", nil)
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"kept":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runCLI("image", "--sbom", archive, "--grype-json", archiveGrype, "-o", "json="+link, "-o", "openvex="+filepath.Join(dir, "r.vex")); code != 3 {
		t.Fatalf("exit %d, want 3: OpenVEX can't name an archive without a tag", code)
	}
	if b, _ := os.ReadFile(target); string(b) != `{"kept":true}` {
		t.Errorf("the symlink's target was changed by a failed run: %q", b)
	}
	assertNoTempFiles(t, dir)
}

func TestMachineOutputOnStdoutHasNoProgress(t *testing.T) {
	sbom, grype := fixture(t, "php:8.4.26-apache", []string{"php:8.4.26-apache"})
	_, stdout, stderr := runCLI("image", "--sbom", sbom, "--grype-json", grype, "-o", "sarif")
	if !json.Valid([]byte(stdout)) || stderr != "" {
		t.Fatalf("stdout valid %v, stderr %q", json.Valid([]byte(stdout)), stderr)
	}
}

func TestOutputList(t *testing.T) {
	var o outputList
	for _, v := range []string{"table", "json=a.json", "sarif=dir/b.sarif"} {
		if err := o.Set(v); err != nil {
			t.Fatalf("%s: %v", v, err)
		}
	}
	if o.String() != "table,json=a.json,sarif=dir/b.sarif" {
		t.Errorf("got %s", o.String())
	}
	for _, bad := range []string{"xml", "", "=x", "json= "} {
		if err := o.Set(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}

// fakeTools puts in place a Syft that fails its first run as a cut-off download does
// and then writes the given SBOM, and a Grype that finds nothing.
func fakeTools(t *testing.T, sbom string) {
	t.Helper()
	dir := t.TempDir()
	count, syft, grype := filepath.Join(dir, "runs"), filepath.Join(dir, "syft"), filepath.Join(dir, "grype")
	syftBody := "#!/bin/sh\n" +
		"n=$(cat '" + count + "' 2>/dev/null || echo 0); echo $((n+1)) > '" + count + "'\n" +
		"if [ \"$n\" = 0 ]; then echo 'could not fetch image: read tcp 10.0.0.2:1->1.2.3.4:443: unexpected EOF' >&2; exit 1; fi\n" +
		"for a; do case \"$a\" in json=*) cp '" + sbom + "' \"${a#json=}\";; esac; done\n"
	grypeBody := "#!/bin/sh\nprev=\nfor a; do if [ \"$prev\" = --file ]; then echo '{\"matches\":[]}' > \"$a\"; fi; prev=$a; done\n" +
		"[ \"$1\" = db ] && echo '{}'\nexit 0\n"
	for p, body := range map[string]string{syft: syftBody, grype: grypeBody} {
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("WHICHPHP_SYFT", syft)
	t.Setenv("WHICHPHP_GRYPE", grype)
}

// A download that is cut off is read once more, and the report says so.
func TestImageRetriesCutOffDownload(t *testing.T) {
	sbom, _ := fixture(t, "php:8.4.26-apache", []string{"php:8.4.26-apache"})
	fakeTools(t, sbom)
	code, stdout, stderr := runCLI("image", "--no-grype", "-o", "json", "registry:php:8.4.26-apache")
	if code != 1 {
		t.Fatalf("exit %d, want 1; stderr: %s", code, stderr)
	}
	var rep struct {
		Image struct{ ReadRetried string }
		Notes []string
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil || rep.Image.ReadRetried != "unexpected EOF" ||
		!strings.Contains(strings.Join(rep.Notes, " "), "Syft's first download of the image was cut off (unexpected EOF), so it was read a second time.") {
		t.Errorf("report: %+v, %v", rep, err)
	}
	if !strings.Contains(stderr, "Syft's download of registry:php:8.4.26-apache was cut off (unexpected EOF); reading it once more") {
		t.Errorf("stderr: %q", stderr)
	}
}

func TestVersionAndUsage(t *testing.T) {
	if code, out, _ := runCLI("version"); code != 0 || !strings.HasPrefix(out, "whichphp ") {
		t.Errorf("version: %d %q", code, out)
	}
	if code, _, errOut := runCLI("image"); code != 3 || !strings.Contains(errOut, "give exactly one image") {
		t.Errorf("no image: %d %q", code, errOut)
	}
	// After "--", a flag-like value is positional; it must still not reach Syft.
	if code, _, errOut := runCLI("image", "--", "--config=/etc/passwd"); code != 3 || !strings.Contains(errOut, "isn't an image reference") {
		t.Errorf("flag-like image: %d %q", code, errOut)
	}
	if code, _, _ := runCLI("nope"); code != 3 {
		t.Errorf("unknown command: %d", code)
	}
}
