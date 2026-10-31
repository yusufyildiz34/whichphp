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
		"-o", "openvex="+filepath.Join(dir, "r.vex.json"), "--vex-author", "Acme")
	if code != 1 {
		t.Fatalf("exit %d, want 1 (action needed); stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "ACTION NEEDED") || !strings.Contains(stdout, "Image:   php:8.4.26-apache") {
		t.Errorf("table:\n%s", stdout)
	}
	for _, name := range []string{"r.json", "r.sarif", "r.vex.json"} {
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
