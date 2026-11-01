package advisory

import (
	"fmt"
	"strings"
	"testing"
)

const header = "packager,branch,distro,fixed,cves,source\n"

func TestParseBackports(t *testing.T) {
	bs, err := ParseBackports([]byte(header +
		"# a comment\n" +
		"Remi,7.4,,7.4.33-31,CVE-2026-109618 CVE-2026-109619,https://example.org/a\n" +
		"Remi,7.3,,none,,https://example.org/b\n" +
		"Freexian ELTS,7.3,debian 10,7.3.31-1~deb10u12,CVE-2026-109619,https://example.org/c\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(bs) != 3 {
		t.Fatalf("got %d rows, want 3", len(bs))
	}
	if b := bs[0]; b.Packager != "Remi" || b.Branch != [2]int{7, 4} || b.Fixed != "7.4.33-31" || !b.Fixes("CVE-2026-109618") || !b.Fixes("CVE-2026-109619") {
		t.Errorf("row 1 = %+v", b)
	}
	if b := bs[1]; b.Fixed != "" || len(b.CVEs) != 0 {
		t.Errorf(`"none" row = %+v, want no fixed version and no CVEs`, b)
	}
	if b := bs[2]; b.Distro != "debian 10" || b.Fixes("CVE-2026-109618") || !b.Fixes("CVE-2026-109619") {
		t.Errorf("row 3 = %+v", b)
	}
}

func TestParseBackportsRejects(t *testing.T) {
	for name, body := range map[string]string{
		"no source":          "Remi,7.4,,7.4.33-31,CVE-2026-109618,\n",
		"http source":        "Remi,7.4,,7.4.33-31,CVE-2026-109618,http://example.org/\n",
		"relative source":    "Remi,7.4,,7.4.33-31,CVE-2026-109618,example.org/a\n",
		"bad branch":         "Remi,7,,7.4.33-31,CVE-2026-109618,https://example.org/\n",
		"branch not numbers": "Remi,x.y,,7.4.33-31,CVE-2026-109618,https://example.org/\n",
		"unknown CVE":        "Remi,7.4,,7.4.33-31,CVE-2026-0001,https://example.org/\n",
		"fixed without CVEs": "Remi,7.4,,7.4.33-31,,https://example.org/\n",
		"empty fixed":        "Remi,7.4,,,CVE-2026-109618,https://example.org/\n",
		"no fix with CVEs":   "Remi,7.3,,none,CVE-2026-109618,https://example.org/\n",
		"other placeholder":  "CloudLinux ea-php,8.2,,1:8.2.34-2.{dist}.cloudlinux.1,CVE-2026-109618,https://example.org/\n",
		"rpm's (none) epoch": "Remi,7.4,,(none):7.4.33-81,CVE-2026-109618,https://example.org/\n",
		"no release":         "Remi,7.4,,7.4.33,CVE-2026-109618,https://example.org/\n",
		"empty release":      "Remi,7.4,,7.4.33-,CVE-2026-109618,https://example.org/\n",
		"not a version":      "Remi,7.4,,v7.4.33-31,CVE-2026-109618,https://example.org/\n",
		"another branch":     "Remi,7.4,,7.3.33-24,CVE-2026-109618,https://example.org/\n",
		"release of tildes":  "Remi,7.4,,7.4.33-~,CVE-2026-109618,https://example.org/\n",
		"release after ~":    "Remi,7.4,,7.4.33-~1,CVE-2026-109618,https://example.org/\n",
		"no packager":        ",7.4,,7.4.33-31,CVE-2026-109618,https://example.org/\n",
		"wrong field count":  "Remi,7.4,7.4.33-31,CVE-2026-109618,https://example.org/\n",
	} {
		if _, err := ParseBackports([]byte(header + body)); err == nil {
			t.Errorf("%s: accepted %q", name, strings.TrimSpace(body))
		}
	}
	if _, err := ParseBackports([]byte("packager,branch,fixed,distro,cves,source\n")); err == nil {
		t.Error("accepted a header with the columns in another order")
	}
}

// The embedded file parsed when the package loaded; a row listed twice, or a branch
// listed both as fixed and as "none", would be an editing mistake the parser can't see.
func TestEmbeddedBackportsAreConsistent(t *testing.T) {
	seen := map[string]bool{}
	noFix := map[string]bool{}
	for _, b := range Backports {
		key := fmt.Sprint(b.Packager, b.Branch, b.Distro)
		if seen[key+b.Fixed] {
			t.Errorf("row listed twice: %+v", b)
		}
		seen[key+b.Fixed] = true
		if b.Fixed == "" {
			noFix[key] = true
		}
	}
	for _, b := range Backports {
		if key := fmt.Sprint(b.Packager, b.Branch, b.Distro); b.Fixed != "" && noFix[key] {
			t.Errorf("%s PHP %d.%d %s is listed both as fixed and as having no fix", b.Packager, b.Branch[0], b.Branch[1], b.Distro)
		}
	}
}

// A distro must be written the way NormalizeRelease reduces it ("debian 10", not
// "debian 10.13"), or the row never applies.
func TestEmbeddedBackportDistros(t *testing.T) {
	for _, b := range Backports {
		if b.Distro == "" {
			continue
		}
		id, ver, ok := strings.Cut(b.Distro, " ")
		if !ok || NormalizeRelease(id, ver) != ver {
			t.Errorf("%s PHP %d.%d: distro %q isn't \"<id> <release>\" as NormalizeRelease gives it", b.Packager, b.Branch[0], b.Branch[1], b.Distro)
		}
	}
}
