package diff

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/yusufyildiz34/whichphp/internal/report"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

// reportJSON is a report as "whichphp image -o json" writes it.
func reportJSON(t *testing.T, r verdict.Report) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := report.JSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// okWith is a report whose action is OK, with one build and these verdicts for the two
// CVEs, as JSON values, in the build and the image alike.
func okWith(v1, v2 string) string {
	return `{"tool":"whichphp","image":{},"action":"OK","php":[{"name":"php","cves":{"CVE-2026-109618":{"verdict":` + v1 + `},"CVE-2026-109619":{"verdict":` + v2 + `}}}],` +
		`"verdicts":{"CVE-2026-109618":` + v1 + `,"CVE-2026-109619":` + v2 + `}}`
}

func TestParseReport(t *testing.T) {
	want := image("php:8.4.26-apache", build("libphp", "8.4.26", "apache-module", verdict.Vulnerable))
	want.Image.Created = "2026-10-01T08:12:00Z"
	got, err := ParseReport(reportJSON(t, want))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip:\n got  %+v\n want %+v", got, want)
	}
	if _, err := ParseReport(append([]byte("\xef\xbb\xbf\n "), reportJSON(t, image("a"))...)); err != nil {
		t.Errorf("a byte order mark and white space: %v", err)
	}

	cases := map[string]string{
		"array":          `[{"tool":"whichphp"}]`,
		"not JSON":       `hello`,
		"truncated":      `{"tool":"whichphp","image":{},"action":"OK"`,
		"another tool":   `{"tool":"trivy","image":{},"action":"OK"}`,
		"cluster report": `{"tool":"whichphp","version":"v0.3.0","context":"lab","action":"OK","workloads":[]}`,
		"index":          `{"schema":1,"tool":"whichphp v0.3.0","entries":[]}`,
		"Syft SBOM":      `{"artifacts":[],"source":{"type":"image"},"descriptor":{"name":"syft"}}`,
		"image a string": `{"tool":"whichphp","image":"php:8.4","action":"OK"}`,
		"no action":      `{"tool":"whichphp","image":{}}`,
		"unknown action": `{"tool":"whichphp","image":{},"action":"MAYBE"}`,
		"wrong type":     `{"tool":"whichphp","image":{},"action":"OK","php":[{"name":7}]}`,
		"php an object":  `{"tool":"whichphp","image":{},"action":"OK","php":{}}`,
		"too many":       `{"tool":"whichphp","image":{},"action":"OK","php":[` + strings.Repeat("{},", maxBuilds) + `{}]}`,
		// An action that contradicts the report's contents.
		"OK, vulnerable":         `{"tool":"whichphp","image":{},"action":"OK","php":[{"name":"php"}],"verdicts":{"CVE-2026-109618":"VULNERABLE"}}`,
		"OK, a vulnerable build": `{"tool":"whichphp","image":{},"action":"OK","php":[{"name":"php","cves":{"CVE-2026-109619":{"verdict":"VULNERABLE_EOL"}}}],"verdicts":{"CVE-2026-109619":"FIXED"}}`,
		"OK without PHP":         `{"tool":"whichphp","image":{},"action":"OK","php":[]}`,
		"no PHP, vulnerable":     `{"tool":"whichphp","image":{},"action":"NO_PHP","verdicts":{"CVE-2026-109618":"VULNERABLE"}}`,
		"no PHP, with PHP":       `{"tool":"whichphp","image":{},"action":"NO_PHP","php":[{"name":"php","cves":{"CVE-2026-109618":{"verdict":"FIXED"}}}]}`,
		// OK only when every verdict, for every CVE, is a fix.
		"OK, unknown":                okWith(`"UNKNOWN"`, `"FIXED"`),
		"OK, ask the vendor":         okWith(`"FIXED"`, `"NEEDS_VENDOR_CONFIRMATION"`),
		"OK, data stale":             okWith(`"DATA_STALE"`, `"DATA_STALE"`),
		"OK, a verdict unknown here": okWith(`"FIXED_SOMEHOW"`, `"FIXED"`),
		"OK, empty verdicts":         okWith(`""`, `""`),
		"OK, keys in another case":   `{"tool":"whichphp","imAge":{},"php":[{"Cves":{"CVE-2026-109618":{},"CVE-2026-109619":{}}}],"verdiCts":{"CVE-2026-109618":"","CVE-2026-109619":""},"ACtion":"OK"}`,
		"OK, a CVE without verdict":  `{"tool":"whichphp","image":{},"action":"OK","php":[{"name":"php","cves":{"CVE-2026-109618":{"verdict":"FIXED"}}}],"verdicts":{"CVE-2026-109618":"FIXED"}}`,
		"OK, a build without verdicts": `{"tool":"whichphp","image":{},"action":"OK","php":[{"name":"php","cves":{"CVE-2026-109618":{"verdict":"FIXED"},"CVE-2026-109619":{"verdict":"FIXED"}}},{"name":"php-fpm"}],` +
			`"verdicts":{"CVE-2026-109618":"FIXED","CVE-2026-109619":"FIXED"}}`,
		"OK, a build's verdict unknown": `{"tool":"whichphp","image":{},"action":"OK","php":[{"name":"php","cves":{"CVE-2026-109618":{"verdict":"FIXED"},"CVE-2026-109619":{"verdict":"UNKNOWN"}}}],` +
			`"verdicts":{"CVE-2026-109618":"FIXED","CVE-2026-109619":"FIXED"}}`,
		"unknown, vulnerable":       `{"tool":"whichphp","image":{},"action":"UNKNOWN","php":[{"name":"php"}],"verdicts":{"CVE-2026-109618":"VULNERABLE"}}`,
		"unknown without PHP":       `{"tool":"whichphp","image":{},"action":"UNKNOWN","verdicts":{"CVE-2026-109618":"UNKNOWN"}}`,
		"action needed without PHP": `{"tool":"whichphp","image":{},"action":"ACTION_NEEDED","verdicts":{"CVE-2026-109618":"VULNERABLE"}}`,
	}
	for name, in := range cases {
		if _, err := ParseReport([]byte(in)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := ParseReport([]byte(cases["OK, vulnerable"])); err == nil || !strings.Contains(err.Error(), "the action OK contradicts its vulnerable verdicts") {
		t.Errorf("the error should say what contradicts what: %v", err)
	}

	// Actions that agree with the contents, including action needed for upload
	// progress alone, as --fail-on-mitigation gives it.
	for name, in := range map[string]string{
		"OK":         okWith(`"FIXED_BY_DISTRO_BACKPORT"`, `"NOT_AFFECTED"`),
		"mitigation": `{"tool":"whichphp","image":{},"action":"ACTION_NEEDED","php":[{"name":"php","cves":{"CVE-2026-109618":{"verdict":"FIXED"}}}],"verdicts":{"CVE-2026-109618":"FIXED"}}`,
		"unknown":    `{"tool":"whichphp","image":{},"action":"UNKNOWN","php":[{"name":"php","cves":{"CVE-2026-109618":{"verdict":"UNKNOWN"}}}]}`,
		"no PHP":     `{"tool":"whichphp","image":{},"action":"NO_PHP","php":null,"verdicts":{}}`,
	} {
		if _, err := ParseReport([]byte(in)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestReadReport(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	rep := image("php:8.4.27-apache", build("php", "8.4.27", "cli", verdict.Fixed))
	for _, name := range []string{"before.json", "before.report", "BEFORE.JSON"} {
		got, ok, err := ReadReport(write(name, reportJSON(t, rep)))
		if err != nil || !ok || got.Image.Input != "php:8.4.27-apache" {
			t.Errorf("%s: ok %v, err %v", name, ok, err)
		}
	}

	// Not report files: the caller scans them as images.
	tar := write("app.tar", append([]byte("app/\x00\x00\x00"), make([]byte, 1024)...))
	for _, arg := range []string{tar, dir, "php:8.4-apache", "docker-archive:" + tar, filepath.Join(dir, "missing")} {
		if _, ok, err := ReadReport(arg); ok || err != nil {
			t.Errorf("%s: ok %v, err %v; want it scanned", arg, ok, err)
		}
	}

	// A mistyped report is an error, never scanned.
	big := append([]byte(`{"tool":"whichphp",`), bytes.Repeat([]byte(" "), maxReportSize)...)
	for name, path := range map[string]string{
		"missing .json":     filepath.Join(dir, "missing.json"),
		"a .json directory": filepath.Join(dir, "dir.json"),
		"cluster report":    write("cluster.json", []byte(`{"tool":"whichphp","context":"lab","action":"OK","workloads":[]}`)),
		"other JSON":        write("sbom", []byte(`{"artifacts":[]}`)),
		"empty .json":       write("empty.json", nil),
		"text in .json":     write("notes.json", []byte("hello")),
		"truncated":         write("cut", reportJSON(t, rep)[:40]),
		"too large":         write("big.json", big),
	} {
		if name == "a .json directory" {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		_, ok, err := ReadReport(path)
		if ok || err == nil {
			t.Errorf("%s: ok %v, err %v; want an error", name, ok, err)
		}
	}
	if _, _, err := ReadReport(filepath.Join(dir, "sbom")); err == nil || !strings.Contains(err.Error(), "whichphp image -o json=") {
		t.Errorf("the error should say how to write a report: %v", err)
	}
}
