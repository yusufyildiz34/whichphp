package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode"

	"github.com/yusufyildiz34/whichphp/internal/phpini"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

// FuzzReports: names, versions, paths and tags in a report come from the image. Every
// output must be produced without a panic, SARIF and OpenVEX must stay valid JSON, a
// purl must be a single token, and no table line may hold a workflow command: "::"
// after leading white space, or "##[" anywhere.
func FuzzReports(f *testing.F) {
	f.Add("php:8.4.26-apache", "php:8.4.26-apache", "libphp", "8.4.26", "/usr/lib/apache2/modules/libphp.so")
	f.Add("/tmp/x.tar", "", "::set-output name=x::y", "8.3.6\n::warning::x", "/a b/[c](d){0}")
	f.Add("registry:GHCR.io/a/b@sha256:0000000000000000000000000000000000000000000000000000000000000000", "a:b", "php", "", "")
	f.Add(" ::warning::x", "\u00a0::error::x", "\u3000::x", "8.4.26##[add-mask]x", "##[group]x")
	f.Add(":", ":x", "#", "#[x", "")
	f.Fuzz(func(t *testing.T, input, tag, name, version, path string) {
		r := verdict.Report{
			Version: "test",
			Image: verdict.Image{Input: input, SourceType: "image", Tags: []string{tag},
				ManifestDigest: "sha256:6985ff1ba36e5fda4a3257bef73c30b04ba657c29cf9cbaafc3f4d4ea0268a51"},
			PHP: []verdict.PHP{{Name: name, Version: version, Paths: []string{path},
				CVEs: cves(verdict.Vulnerable, version)}},
			Settings: map[string]phpini.Setting{phpini.UploadProgress: {Effective: "on", Why: path}},
			Action:   verdict.ActionNeeded,
		}
		if p := imagePURL(r); p != "" && (!strings.HasPrefix(p, "pkg:oci/") || strings.ContainsAny(p, " \n\t")) {
			t.Fatalf("bad purl %q", p)
		}
		var s, v, tb bytes.Buffer
		if err := SARIF(&s, r); err != nil || !json.Valid(s.Bytes()) {
			t.Fatalf("SARIF: %v", err)
		}
		if err := OpenVEX(&v, r, VEXOptions{}); err == nil && !json.Valid(v.Bytes()) {
			t.Fatal("OpenVEX output isn't valid JSON")
		}
		if err := Table(&tb, r); err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(tb.String(), "\n") {
			if strings.HasPrefix(strings.TrimLeftFunc(line, unicode.IsSpace), "::") || strings.Contains(line, "##[") {
				t.Fatalf("table line holds a workflow command: %q", line)
			}
		}
	})
}
