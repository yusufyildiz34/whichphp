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

// FuzzReports: names, versions, paths, tags and purls in a report come from the image.
// Every output must be produced without a panic, SARIF, OpenVEX and CycloneDX must
// stay valid JSON, CycloneDX bom-refs must stay unique, a purl must be a single token,
// and no table line may hold a workflow command: "::" after leading white space, or
// "##[" anywhere.
func FuzzReports(f *testing.F) {
	f.Add("php:8.4.26-apache", "php:8.4.26-apache", "libphp", "8.4.26", "/usr/lib/apache2/modules/libphp.so")
	f.Add("/tmp/x.tar", "", "::set-output name=x::y", "8.3.6\n::warning::x", "/a b/[c](d){0}")
	f.Add("registry:GHCR.io/a/b@sha256:0000000000000000000000000000000000000000000000000000000000000000", "a:b", "php", "", "")
	f.Add(" ::warning::x", "\u00a0::error::x", "\u3000::x", "8.4.26##[add-mask]x", "##[group]x")
	f.Add(":", ":x", "#", "#[x", "")
	f.Add("\xc1", "\xd5", "0", "0", "0")
	f.Fuzz(func(t *testing.T, input, tag, name, version, path string) {
		r := verdict.Report{
			Version: "test",
			Image: verdict.Image{Input: input, SourceType: "image", Tags: []string{tag},
				ManifestDigest: "sha256:6985ff1ba36e5fda4a3257bef73c30b04ba657c29cf9cbaafc3f4d4ea0268a51"},
			// The second build's purl is the tag, so it can collide with the first's.
			PHP: []verdict.PHP{{Name: name, Version: version, Paths: []string{path},
				CVEs: cves(verdict.Vulnerable, version)},
				{Name: name, Version: version, PURL: tag, Paths: []string{path},
					CVEs: cves(verdict.FixedByDistroBackport, path)}},
			Settings: map[string]phpini.Setting{phpini.UploadProgress: {Effective: "on", Why: path}},
			Action:   verdict.ActionNeeded,
		}
		if p := imagePURL(r); p != "" && (!strings.HasPrefix(p, "pkg:oci/") || strings.ContainsAny(p, " \n\t")) {
			t.Fatalf("bad purl %q", p)
		}
		var s, v, c, tb bytes.Buffer
		if err := SARIF(&s, r); err != nil || !json.Valid(s.Bytes()) {
			t.Fatalf("SARIF: %v", err)
		}
		if err := OpenVEX(&v, r, VEXOptions{}); err == nil && !json.Valid(v.Bytes()) {
			t.Fatal("OpenVEX output isn't valid JSON")
		}
		// CycloneDX needs no image name, so it must always succeed.
		var bom cdxBOM
		if err := CycloneDX(&c, r, VEXOptions{}); err != nil || !json.Valid(c.Bytes()) {
			t.Fatalf("CycloneDX: %v", err)
		}
		if err := json.Unmarshal(c.Bytes(), &bom); err != nil {
			t.Fatal(err)
		}
		if err := checkRefs(bom); err != nil {
			t.Fatal(err)
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
