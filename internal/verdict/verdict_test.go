package verdict

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/yusufyildiz34/whichphp/internal/grypejson"
	"github.com/yusufyildiz34/whichphp/internal/syftjson"
)

const (
	cve18 = "CVE-2026-109618"
	cve19 = "CVE-2026-109619"
)

var now = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

func TestByVersion(t *testing.T) {
	cases := []struct {
		version string
		cve     string
		want    Verdict
	}{
		{"8.4.26", cve18, Vulnerable}, // official-prefix
		{"8.4.27", cve18, Fixed},      // official-fixed
		{"8.5.11", cve19, Vulnerable},
		{"8.5.12", cve19, Fixed},
		{"8.3.35", cve18, Vulnerable},
		{"8.3.36", cve18, Fixed},
		{"8.2.34", cve18, Vulnerable},
		{"8.2.35", cve18, Fixed},
		{"8.1.34", cve18, VulnerableEOL}, // eol-branch
		{"7.4.33", cve19, VulnerableEOL},
		{"5.6.40", cve18, NotAffected},     // 109618 starts at 7.3.0
		{"5.6.40", cve19, VulnerableEOL},   // 109619 starts at 5.4.0
		{"8.2.29-2", cve18, Vulnerable},    // packaging-suffix
		{"The PHP Group", cve18, Unknown},  // php-group-string
		{"8.4.26-dev", cve18, Vulnerable},  // prerelease below the fix
		{"8.4.27RC1", cve18, Unknown},      // prerelease at the fix: unproven
		{"8.4.27-1.devuan1", cve18, Fixed}, // distro-dev-suffix
		{"8.6.0RC3", cve18, Vulnerable},
		{"8.6.0RC4", cve18, Fixed},
		{"8.6.0", cve18, Fixed},
		{"8.6.0-dev", cve18, Unknown},
		{"8.7.0", cve18, Fixed},
	}
	for _, c := range cases {
		got, why := ByVersion(c.version, c.cve)
		if got != c.want {
			t.Errorf("ByVersion(%q, %s) = %s (%s), want %s", c.version, c.cve, got, why, c.want)
		}
	}
}

type art struct {
	name, version, typ, purl, cpe, path string
}

func doc(t *testing.T, distro, distroVer, created string, files map[string]string, arts ...art) *syftjson.Document {
	t.Helper()
	type cpe struct {
		CPE string `json:"cpe"`
	}
	type loc struct {
		Path string `json:"path"`
	}
	type a struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Type      string `json:"type"`
		PURL      string `json:"purl"`
		CPEs      []cpe  `json:"cpes"`
		Locations []loc  `json:"locations"`
	}
	type f struct {
		Location loc    `json:"location"`
		Contents string `json:"contents"`
	}
	cfg, _ := json.Marshal(map[string]any{"created": created, "config": map[string]any{"Cmd": []string{"apache2-foreground"}}})
	md, _ := json.Marshal(map[string]any{"userInput": "example:test", "architecture": "amd64", "config": cfg})
	raw := map[string]any{
		"descriptor": map[string]string{"name": "syft", "version": "1.55.0"},
		"distro":     map[string]string{"id": distro, "versionID": distroVer},
		"source":     map[string]any{"type": "image", "metadata": json.RawMessage(md)},
	}
	var as []a
	for _, x := range arts {
		item := a{Name: x.name, Version: x.version, Type: x.typ, PURL: x.purl, Locations: []loc{{x.path}}}
		if x.cpe != "" {
			item.CPEs = []cpe{{x.cpe}}
		}
		as = append(as, item)
	}
	raw["artifacts"] = as
	var fs []f
	for p, c := range files {
		fs = append(fs, f{Location: loc{p}, Contents: base64.StdEncoding.EncodeToString([]byte(c))})
	}
	raw["files"] = fs
	b, _ := json.Marshal(raw)
	d, err := syftjson.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func official(version string) art {
	return art{"php-cli", version, "binary", "pkg:generic/php-cli@" + version, "cpe:2.3:a:php:php:" + version + ":*:*:*:*:*:*:*", "/usr/local/bin/php"}
}

func TestOfficialPrefixImage(t *testing.T) {
	d := doc(t, "debian", "13.7", "2026-10-01T00:00:00Z", nil, official("8.4.26"))
	r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now})
	if r.Verdicts[cve18] != Vulnerable || r.Action != ActionNeeded || r.Action.ExitCode() != 1 {
		t.Fatalf("got %v / %s", r.Verdicts, r.Action)
	}
	if r.Settings["session.upload_progress.enabled"].Effective != "unknown" {
		t.Fatalf("without file contents the setting must be unknown, got %+v", r.Settings)
	}
	if r.Image.BuiltBeforeFix == nil || !*r.Image.BuiltBeforeFix {
		t.Fatal("image created Oct 1 should be built before the fix")
	}
}

func TestOfficialFixedWithMitigationFile(t *testing.T) {
	files := map[string]string{"/usr/local/etc/php/conf.d/mitigate.ini": "session.upload_progress.enabled = 0\n"}
	d := doc(t, "debian", "13.7", "2026-10-22T00:00:00Z", files, official("8.4.27"))
	r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now})
	if r.Verdicts[cve18] != Fixed || r.Action != ActionOK || r.Settings["session.upload_progress.enabled"].Effective != "off" {
		t.Fatalf("got %v / %s / %+v", r.Verdicts, r.Action, r.Settings)
	}
}

func ubuntuBackport() art {
	return art{"php8.3-cli", "8.3.6-0ubuntu0.24.04.13", "deb", "pkg:deb/ubuntu/php8.3-cli@8.3.6-0ubuntu0.24.04.13?distro=ubuntu-24.04&upstream=php8.3", "", "/var/lib/dpkg/status"}
}

func TestUbuntuBackport(t *testing.T) {
	d := doc(t, "ubuntu", "24.04", "2026-10-25T00:00:00Z", nil, ubuntuBackport())
	feed := map[string]grypejson.FeedStatus{
		cve18: {Listed: true, Package: "php8.3", FixVersion: "8.3.6-0ubuntu0.24.04.13"},
		cve19: {Listed: true, Package: "php8.3", FixVersion: "8.3.6-0ubuntu0.24.04.13"},
	}
	r := Evaluate(Inputs{Doc: d, GrypeRan: true, Hits: map[grypejson.Key][]grypejson.Hit{}, Feed: feed, Now: now})
	if r.Verdicts[cve18] != FixedByDistroBackport || r.Action != ActionOK {
		t.Fatalf("got %v / %s", r.Verdicts, r.Action)
	}
}

func TestUbuntuFeedDoesNotListCVE(t *testing.T) {
	d := doc(t, "ubuntu", "24.04", "2026-10-25T00:00:00Z", nil, ubuntuBackport())
	feed := map[string]grypejson.FeedStatus{cve18: {Listed: false}, cve19: {Listed: false}}
	r := Evaluate(Inputs{Doc: d, GrypeRan: true, Feed: feed, Now: now})
	if r.Verdicts[cve18] != NeedsVendorConfirmation || r.Action != ActionUnknown || r.Action.ExitCode() != 2 {
		t.Fatalf("got %v / %s", r.Verdicts, r.Action)
	}
}

func TestDistroMatchIsVulnerable(t *testing.T) {
	a := art{"php8.2-fpm", "8.2.29-1~deb12u1", "deb", "", "", "/var/lib/dpkg/status"}
	d := doc(t, "debian", "12.12", "2026-10-25T00:00:00Z", nil, a)
	hits := map[grypejson.Key][]grypejson.Hit{
		{Name: a.name, Version: a.version}: {{CVE: cve18, FixVersions: []string{"8.2.35-1~deb12u1"}}},
	}
	r := Evaluate(Inputs{Doc: d, GrypeRan: true, Hits: hits, Now: now})
	if r.PHP[0].CVEs[cve18].Verdict != Vulnerable || r.PHP[0].SAPI != "fpm" {
		t.Fatalf("got %+v", r.PHP[0])
	}
}

func TestEOLDistroPredatingFix(t *testing.T) {
	a := art{"php7.3-cli", "7.3.27-1~deb10u1", "deb", "", "", "/var/lib/dpkg/status"}
	d := doc(t, "debian", "10.1", "2021-03-01T00:00:00Z", nil, a)
	r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now})
	if r.Verdicts[cve18] != VulnerableEOL || r.Distro.Support != "end-of-life" {
		t.Fatalf("got %v / %+v", r.Verdicts, r.Distro)
	}
}

func TestSuryBuildFollowsUpstream(t *testing.T) {
	a := art{"php8.3-cli", "8.3.35-1+ubuntu24.04.1+deb.sury.org+1", "deb", "", "", "/var/lib/dpkg/status"}
	d := doc(t, "ubuntu", "24.04", "2026-10-15T00:00:00Z", nil, a)
	r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now})
	if r.PHP[0].Source != SourceThirdParty || r.PHP[0].Provider != "Sury" || r.Verdicts[cve18] != Vulnerable {
		t.Fatalf("got %+v / %v", r.PHP[0], r.Verdicts)
	}
}

func TestMultiSAPI(t *testing.T) {
	fpm := art{"php-fpm", "8.4.26", "binary", "pkg:generic/php-fpm@8.4.26", "cpe:2.3:a:php:php:8.4.26:*:*:*:*:*:*:*", "/usr/local/sbin/php-fpm"}
	d := doc(t, "debian", "13.7", "2026-10-25T00:00:00Z", nil, official("8.4.27"), fpm)
	r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now})
	if len(r.PHP) != 2 || r.Verdicts[cve18] != Vulnerable || r.Action != ActionNeeded {
		t.Fatalf("got %d PHPs, %v / %s", len(r.PHP), r.Verdicts, r.Action)
	}
}

func TestStaleDatabase(t *testing.T) {
	d := doc(t, "ubuntu", "24.04", "2026-10-25T00:00:00Z", nil, ubuntuBackport())
	r := Evaluate(Inputs{Doc: d, GrypeRan: true, DBBuilt: now.Add(-10 * 24 * time.Hour), MaxDBAge: 7 * 24 * time.Hour, Now: now})
	if r.Verdicts[cve18] != DataStale || r.Action != ActionUnknown {
		t.Fatalf("got %v / %s", r.Verdicts, r.Action)
	}
}

func TestNoGrypeMeansUnknownForDistro(t *testing.T) {
	d := doc(t, "ubuntu", "24.04", "2026-10-25T00:00:00Z", nil, ubuntuBackport())
	r := Evaluate(Inputs{Doc: d, GrypeRan: false, Now: now})
	if r.Verdicts[cve18] != Unknown {
		t.Fatalf("got %v", r.Verdicts)
	}
}

func TestBitnamiDuplicateMerged(t *testing.T) {
	a1 := art{"php", "8.4.10-2", "bitnami", "pkg:bitnami/php@8.4.10-2", "cpe:2.3:a:php:php:8.4.10-2:*:*:*:*:*:*:*", "/opt/bitnami/.bitnami_components.json"}
	a2 := art{"php", "8.4.10-2", "bitnami", "pkg:bitnami/php@8.4.10-2", "cpe:2.3:*:php:php:8.4.10:*:*:*:*:*:*:*", "/opt/bitnami/php/.spdx-php.spdx"}
	d := doc(t, "debian", "12.11", "2025-07-23T00:00:00Z", nil, a1, a2)
	r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now})
	if len(r.PHP) != 1 || len(r.PHP[0].Paths) != 2 || r.Verdicts[cve18] != Vulnerable {
		t.Fatalf("got %+v / %v", r.PHP, r.Verdicts)
	}
}

func TestNoPHP(t *testing.T) {
	d := doc(t, "debian", "13.7", "2026-10-25T00:00:00Z", nil)
	r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now})
	if r.Action != ActionNoPHP || r.Action.ExitCode() != 0 {
		t.Fatalf("got %s", r.Action)
	}
}

func TestFailOnMitigation(t *testing.T) {
	d := doc(t, "debian", "13.7", "2026-10-25T00:00:00Z", map[string]string{"/usr/local/etc/php/conf.d/docker-php-ext-sodium.ini": "extension=sodium\n"}, official("8.4.27"))
	r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now, FailOnMitigation: true})
	if r.Action != ActionNeeded {
		t.Fatalf("upload_progress on with --fail-on-mitigation should need action, got %s (%+v)", r.Action, r.Settings)
	}
}
