package diff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode"

	"github.com/yusufyildiz34/whichphp/internal/advisory"
	"github.com/yusufyildiz34/whichphp/internal/phpini"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

const (
	cve1 = "CVE-2026-109618"
	cve2 = "CVE-2026-109619"
)

// build is one PHP build with a verdict per CVE, in advisory order; one verdict
// applies to every CVE.
func build(name, version, sapi string, vs ...verdict.Verdict) verdict.PHP {
	cves := map[string]verdict.CVEResult{}
	for i, c := range advisory.CVEs {
		cves[c] = verdict.CVEResult{Verdict: vs[min(i, len(vs)-1)]}
	}
	return verdict.PHP{Name: name, Version: version, Source: verdict.SourceUpstream, SAPI: sapi, CVEs: cves}
}

// backport is a distro build fixed by a backport. Unconfirmed, the fix rests only on
// the absence of a Grype match.
func backport(name, version, sapi string, unconfirmed bool) verdict.PHP {
	p := build(name, version, sapi, verdict.FixedByDistroBackport)
	p.Source = verdict.SourceDistro
	for c, r := range p.CVEs {
		r.Unconfirmed = unconfirmed
		p.CVEs[c] = r
	}
	return p
}

// image is a report of an image with these builds. Its verdicts and action follow from
// the builds as verdict.Evaluate sets them, and upload progress is on, the default.
func image(tag string, builds ...verdict.PHP) verdict.Report {
	r := verdict.Report{
		Tool: "whichphp", Version: "test",
		Image:    verdict.Image{Input: tag, SourceType: "image", Tags: []string{tag}},
		PHP:      builds,
		Verdicts: map[string]verdict.Verdict{},
		Action:   verdict.ActionNoPHP,
	}
	if len(builds) == 0 {
		return r
	}
	for _, p := range builds {
		for c, res := range p.CVEs {
			r.Verdicts[c] = verdict.Worse(r.Verdicts[c], res.Verdict)
		}
	}
	r.Settings = map[string]phpini.Setting{phpini.UploadProgress: {Effective: "on"}}
	r.Action = verdict.ActionOK
	for _, v := range r.Verdicts {
		if v.IsVulnerable() {
			r.Action = verdict.ActionNeeded
		} else if v.IsUncertain() && r.Action == verdict.ActionOK {
			r.Action = verdict.ActionUnknown
		}
	}
	return r
}

// pairs describes each build of a comparison in one line, in its order.
func pairs(d Diff) []string {
	text := func(p *PHP) string {
		if p == nil {
			return "-"
		}
		return p.Name + " " + p.Version
	}
	var out []string
	for _, b := range d.PHP {
		head := b.Change
		if b.Match != "" {
			head += " " + b.Match
		}
		out = append(out, fmt.Sprintf("%s: %s > %s", head, text(b.Before), text(b.After)))
	}
	return out
}

// distro is a distro build of a packager (provider), or of the distro itself.
func distro(name, version, sapi, provider string, v verdict.Verdict) verdict.PHP {
	p := build(name, version, sapi, v)
	p.Source, p.Provider = verdict.SourceDistro, provider
	return p
}

// kinds is pairs with each build's source and provider.
func kinds(d Diff) []string {
	text := func(p *PHP) string {
		if p == nil {
			return "-"
		}
		return fmt.Sprintf("%s %s (%s)", p.Name, p.Version, strings.TrimSpace(p.Source+" "+p.Provider))
	}
	var out []string
	for _, b := range d.PHP {
		out = append(out, fmt.Sprintf("%s %s: %s > %s", b.Change, b.Match, text(b.Before), text(b.After)))
	}
	return out
}

func TestMatching(t *testing.T) {
	vuln, fixed := verdict.Vulnerable, verdict.Fixed
	cases := []struct {
		name          string
		before, after []verdict.PHP
		want          []string
	}{
		{"a new version of the same build",
			[]verdict.PHP{build("php-cli", "8.4.26", "cli", vuln)},
			[]verdict.PHP{build("php-cli", "8.4.27", "cli", fixed)},
			[]string{"changed name: php-cli 8.4.26 > php-cli 8.4.27"}},
		{"the same build",
			[]verdict.PHP{build("php-cli", "8.4.27", "cli", fixed)},
			[]verdict.PHP{build("php-cli", "8.4.27", "cli", fixed)},
			[]string{"unchanged name: php-cli 8.4.27 > php-cli 8.4.27"}},
		{"a package named for its PHP branch",
			[]verdict.PHP{build("php8.3-fpm", "8.3.6-0ubuntu0.24.04.13", "fpm", fixed), build("php8.3-cli", "8.3.6-0ubuntu0.24.04.13", "cli", fixed)},
			[]verdict.PHP{build("php8.4-cli", "8.4.5-1ubuntu1", "cli", fixed), build("php8.4-fpm", "8.4.5-1ubuntu1", "fpm", fixed)},
			[]string{
				"changed family: php8.3-cli 8.3.6-0ubuntu0.24.04.13 > php8.4-cli 8.4.5-1ubuntu1",
				"changed family: php8.3-fpm 8.3.6-0ubuntu0.24.04.13 > php8.4-fpm 8.4.5-1ubuntu1",
			}},
		{"Alpine and cPanel names",
			[]verdict.PHP{build("php83-fpm", "8.3.35-r0", "fpm", vuln), build("ea-php81-php-cli", "8.1.34-4.cpanel", "cli", vuln)},
			[]verdict.PHP{build("ea-php82-php-cli", "8.2.35-1.cpanel", "cli", fixed), build("php84-fpm", "8.4.27-r0", "fpm", fixed)},
			[]string{
				"changed family: ea-php81-php-cli 8.1.34-4.cpanel > ea-php82-php-cli 8.2.35-1.cpanel",
				"changed family: php83-fpm 8.3.35-r0 > php84-fpm 8.4.27-r0",
			}},
		{"another package for the same SAPI",
			[]verdict.PHP{build("libapache2-mod-php8.2", "8.2.29-1~deb12u1", "apache-module", vuln)},
			[]verdict.PHP{build("libphp", "8.4.27", "apache-module", fixed)},
			[]string{"changed sapi: libapache2-mod-php8.2 8.2.29-1~deb12u1 > libphp 8.4.27"}},
		{"two candidates for one SAPI are not guessed between",
			[]verdict.PHP{build("libapache2-mod-php8.2", "8.2.29-1~deb12u1", "apache-module", vuln)},
			[]verdict.PHP{build("libphp", "8.4.27", "apache-module", fixed), build("mod_php", "8.3.36", "apache-module", fixed)},
			[]string{
				"added: - > libphp 8.4.27",
				"added: - > mod_php 8.3.36",
				"removed: libapache2-mod-php8.2 8.2.29-1~deb12u1 > -",
			}},
		{"the same name for another SAPI is another build",
			[]verdict.PHP{build("php", "8.4.26", "cli", vuln)},
			[]verdict.PHP{build("php", "8.4.27", "fpm", fixed)},
			[]string{"added: - > php 8.4.27", "removed: php 8.4.26 > -"}},
		{"the closest versions pair first",
			[]verdict.PHP{build("php", "8.3.10", "cli", vuln), build("php", "8.4.26", "cli", vuln)},
			[]verdict.PHP{build("php", "8.4.27", "cli", fixed), build("php", "8.3.36", "cli", fixed)},
			[]string{"changed name: php 8.4.26 > php 8.4.27", "changed name: php 8.3.10 > php 8.3.36"}},
		{"an exact match beats a closer version",
			[]verdict.PHP{build("php", "8.4.26", "cli", vuln), build("php", "8.4.27", "cli", fixed)},
			[]verdict.PHP{build("php", "8.4.27", "cli", fixed)},
			[]string{"removed: php 8.4.26 > -", "unchanged name: php 8.4.27 > php 8.4.27"}},
		{"the same build from two sources pairs with its own kind",
			[]verdict.PHP{distro("php-cli", "8.3.6", "cli", "", vuln), build("php-cli", "8.3.6", "cli", vuln), distro("php-cli", "8.3.6", "cli", "Sury", vuln)},
			[]verdict.PHP{build("php-cli", "8.3.6", "cli", fixed), distro("php-cli", "8.3.6", "cli", "Sury", fixed), distro("php-cli", "8.3.6", "cli", "", fixed)},
			[]string{
				"unchanged name: php-cli 8.3.6 (upstream-build) > php-cli 8.3.6 (upstream-build)",
				"unchanged name: php-cli 8.3.6 (distro Sury) > php-cli 8.3.6 (distro Sury)",
				"unchanged name: php-cli 8.3.6 (distro) > php-cli 8.3.6 (distro)",
			}},
		{"added, removed and changed, in that order",
			[]verdict.PHP{build("php-fpm", "8.4.27", "fpm", fixed), build("php-cgi", "8.4.26", "cgi", vuln), build("php-cli", "8.4.26", "cli", vuln)},
			[]verdict.PHP{build("php-cli", "8.4.27", "cli", fixed), build("php-fpm", "8.4.27", "fpm", fixed), build("frankenphp", "8.4.27", "embedded", fixed)},
			[]string{
				"changed name: php-cli 8.4.26 > php-cli 8.4.27",
				"added: - > frankenphp 8.4.27",
				"removed: php-cgi 8.4.26 > -",
				"unchanged name: php-fpm 8.4.27 > php-fpm 8.4.27",
			}},
	}
	for _, c := range cases {
		d := Compare(image("before", c.before...), image("after", c.after...), Options{})
		got := pairs(d)
		if strings.Contains(c.name, "sources") {
			got = kinds(d)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got  %q\n want %q", c.name, got, c.want)
		}
	}
}

func TestFamily(t *testing.T) {
	for name, want := range map[string]string{
		"php8.3-fpm": "php-fpm", "php83-fpm": "php-fpm", "PHP8.4-CLI": "php-cli", "php-fpm": "php-fpm",
		"libapache2-mod-php8.3": "libapache2-mod-php", "ea-php81-php-fpm": "ea-php-php-fpm",
		"alt-php74-cli": "alt-php-cli", "libphp7": "libphp", "php": "php",
	} {
		if got := family(name); got != want {
			t.Errorf("family(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestChanges(t *testing.T) {
	before := image("php:8.4.26-apache",
		build("libphp", "8.4.26", "apache-module", verdict.Vulnerable),
		build("php8.3-cli", "8.3.6-0ubuntu0.24.04.13", "cli", verdict.NeedsVendorConfirmation))
	before.Image.ManifestDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	before.Image.Created = "2026-10-01T08:00:00Z"
	after := image("php:8.4.27-apache",
		build("libphp", "8.4.27", "apache-module", verdict.Fixed),
		build("php8.3-cli", "8.3.6-0ubuntu0.24.04.13", "cli", verdict.FixedByDistroBackport))
	after.Image.ManifestDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	after.Image.Created = "2026-10-22T03:00:00Z"
	after.Settings[phpini.UploadProgress] = phpini.Setting{Effective: "off"}

	d := Compare(before, after, Options{})
	if d.Before.Name != "php:8.4.26-apache" || d.After.Name != "php:8.4.27-apache" ||
		d.Before.Digest != before.Image.ManifestDigest || d.After.Digest != after.Image.ManifestDigest ||
		d.Before.Created != "2026-10-01T08:00:00Z" || d.After.Created != "2026-10-22T03:00:00Z" {
		t.Errorf("images: %+v %+v", d.Before, d.After)
	}
	if d.Action != (Change{"ACTION_NEEDED", "OK"}) || d.UploadProgress != (Change{"on", "off"}) {
		t.Errorf("action %+v, upload progress %+v", d.Action, d.UploadProgress)
	}
	if d.Verdicts[cve1] != (VerdictChange{Before: "VULNERABLE", After: "FIXED_BY_DISTRO_BACKPORT"}) || len(d.Verdicts) != 2 {
		t.Errorf("verdicts: %+v", d.Verdicts)
	}
	if got := pairs(d); !reflect.DeepEqual(got, []string{
		"changed name: libphp 8.4.26 > libphp 8.4.27",
		"unchanged name: php8.3-cli 8.3.6-0ubuntu0.24.04.13 > php8.3-cli 8.3.6-0ubuntu0.24.04.13",
	}) {
		t.Fatalf("builds: %q", got)
	}
	// An unchanged build can still change its verdicts, when the data behind them did.
	if d.PHP[0].CVEs[cve2] != (VerdictChange{Before: "VULNERABLE", After: "FIXED"}) || d.PHP[1].CVEs[cve1] != (VerdictChange{Before: "NEEDS_VENDOR_CONFIRMATION", After: "FIXED_BY_DISTRO_BACKPORT"}) {
		t.Errorf("build verdicts: %+v %+v", d.PHP[0].CVEs, d.PHP[1].CVEs)
	}
	if d.Outcome != Fixed || d.Summary != "Fixed by this change" || d.ExitCode() != 0 {
		t.Errorf("outcome %s %q, exit %d", d.Outcome, d.Summary, d.ExitCode())
	}
}

func TestOutcomes(t *testing.T) {
	var (
		vulnerable = build("php", "8.4.26", "cli", verdict.Vulnerable)
		older      = build("php", "8.4.25", "cli", verdict.Vulnerable)
		fixed      = build("php", "8.4.27", "cli", verdict.Fixed)
		newer      = build("php", "8.4.28", "cli", verdict.Fixed)
		unknown    = build("php", "8.4.27RC1", "cli", verdict.Unknown)
		unknown2   = build("php", "8.4.28RC1", "cli", verdict.Unknown)
		// PHP 7.2 predates the first affected release of one CVE, 7.4 doesn't.
		php72 = build("php", "7.2.34", "cli", verdict.NotAffected, verdict.VulnerableEOL)
		php74 = build("php", "7.4.33", "cli", verdict.VulnerableEOL)
		// One CVE better, the other worse.
		mixedA = build("php", "1.0.0", "cli", verdict.Vulnerable, verdict.Fixed)
		mixedB = build("php", "1.0.1", "cli", verdict.Fixed, verdict.Vulnerable)
		// Distro builds whose fix shows only as a backport.
		confirmed   = backport("php", "8.3.6-0ubuntu0.24.04.13", "cli", false)
		unconfirmed = backport("php", "8.3.6-0ubuntu0.24.04.13", "cli", true)
	)
	off := func(r verdict.Report) verdict.Report {
		r.Settings = map[string]phpini.Setting{phpini.UploadProgress: {Effective: "off"}}
		return r
	}
	cases := []struct {
		name          string
		before, after verdict.Report
		want          Outcome
		exit          int
	}{
		{"fixed", image("a", vulnerable), image("b", fixed), Fixed, 0},
		{"proven fixed", image("a", unknown), image("b", fixed), Fixed, 0},
		{"PHP removed", image("a", vulnerable), image("b"), NoPHPAfter, 0},
		{"PHP removed from a fixed image", image("a", fixed), image("b"), NoPHPAfter, 0},
		{"fixed by a confirmed backport", image("a", vulnerable), image("b", confirmed), Fixed, 0},
		{"an unconfirmed backport", image("a", vulnerable), image("b", unconfirmed), Improved, 0},
		{"an unconfirmed backport after unknown", image("a", unknown), image("b", unconfirmed), Improved, 0},
		{"improved", image("a", vulnerable), image("b", unknown), Improved, 2},
		{"still vulnerable", image("a", older), image("b", vulnerable), StillVulnerable, 1},
		{"still unknown", image("a", unknown), image("b", unknown2), StillUnknown, 2},
		{"still OK", image("a", fixed), image("b", newer), StillOK, 0},
		{"fixed PHP added", image("a"), image("b", fixed), StillOK, 0},
		{"got worse", image("a", fixed), image("b", vulnerable), GotWorse, 1},
		{"vulnerable PHP added", image("a"), image("b", vulnerable), GotWorse, 1},
		{"unknown after fixed", image("a", fixed), image("b", unknown), GotWorse, 2},
		{"a CVE got worse", image("a", php72), image("b", php74), GotWorse, 1},
		{"one CVE better, one worse", image("a", mixedA), image("b", mixedB), StillVulnerable, 1},
		{"the mitigation turned back on", off(image("a", fixed)), image("b", newer), GotWorse, 0},
		{"the mitigation turned on", image("a", vulnerable), off(image("b", vulnerable)), StillVulnerable, 1},
		{"no PHP change", image("a", vulnerable), image("b", vulnerable), NoPHPChange, 1},
		{"no PHP change, fixed", image("a", fixed), image("b", fixed), NoPHPChange, 0},
		{"no PHP in either", image("a"), image("b"), NoPHPChange, 0},
	}
	for _, c := range cases {
		d := Compare(c.before, c.after, Options{})
		if d.Outcome != c.want || d.Summary != summaries[c.want] || d.ExitCode() != c.exit {
			t.Errorf("%s: %s %q, exit %d; want %s, exit %d", c.name, d.Outcome, d.Summary, d.ExitCode(), c.want, c.exit)
		}
		if d.ExitCode() != c.after.Action.ExitCode() {
			t.Errorf("%s: exit %d, but the after image's is %d", c.name, d.ExitCode(), c.after.Action.ExitCode())
		}
	}
}

func TestExitCodeOfAnUnknownAction(t *testing.T) {
	after := image("b", build("php", "8.4.27", "cli", verdict.Fixed))
	after.Action = "SOMETHING_NEW"
	if d := Compare(image("a"), after, Options{}); d.ExitCode() != 2 {
		t.Errorf("an action whichphp doesn't know must be unknown, exit 2; got %d", d.ExitCode())
	}
}

func TestFailOnMitigation(t *testing.T) {
	before := image("a", build("php", "8.4.26", "cli", verdict.Vulnerable))
	after := image("b", build("php", "8.4.27", "cli", verdict.Fixed))
	if d := Compare(before, after, Options{}); d.ExitCode() != 0 || d.Outcome != Fixed {
		t.Fatalf("without the option: %s, exit %d", d.Outcome, d.ExitCode())
	}
	d := Compare(before, after, Options{FailOnMitigation: true})
	if d.ExitCode() != 1 || d.Action.After != "ACTION_NEEDED" || d.Outcome != StillVulnerable {
		t.Errorf("upload progress on must need action: %s %+v, exit %d", d.Outcome, d.Action, d.ExitCode())
	}
	after.Settings[phpini.UploadProgress] = phpini.Setting{Effective: "off"}
	if d := Compare(before, after, Options{FailOnMitigation: true}); d.ExitCode() != 0 || d.Outcome != Fixed {
		t.Errorf("upload progress off: %s, exit %d", d.Outcome, d.ExitCode())
	}
	if d := Compare(image("a"), image("b"), Options{FailOnMitigation: true}); d.ExitCode() != 0 {
		t.Errorf("no PHP: exit %d", d.ExitCode())
	}
}

func TestNotes(t *testing.T) {
	before := image("php:8.4-apache", build("php", "8.4.27", "cli", verdict.Fixed))
	after := before
	after.Image.Architecture, before.Image.Architecture = "arm64", "amd64"
	after.Image.ImageID = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	before.Image.ImageID = after.Image.ImageID
	after.Version = "v0.4.0"
	d := Compare(before, after, Options{})
	all := strings.Join(d.Notes, "\n")
	for _, want := range []string{"different architectures, amd64 and arm64", "the same image", "different versions of whichphp, test and v0.4.0"} {
		if !strings.Contains(all, want) {
			t.Errorf("notes lack %q:\n%s", want, all)
		}
	}
	if d := Compare(image("a"), image("b"), Options{}); len(d.Notes) != 0 {
		t.Errorf("unexpected notes: %q", d.Notes)
	}

	// A report made by another version of whichphp than the one running follows that
	// version's rules.
	old := image("a")
	old.Version = "v0.3.0"
	unnamed := image("b")
	unnamed.Version = ""
	d = Compare(old, unnamed, Options{Version: "v0.4.0"})
	all = strings.Join(d.Notes, "\n")
	for _, want := range []string{
		"The before report was made by whichphp v0.3.0, not by this whichphp v0.4.0; its verdicts follow the rules of that version",
		"The after report doesn't say which version of whichphp made it",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("notes lack %q:\n%s", want, all)
		}
	}
	if d.Version != "v0.4.0" {
		t.Errorf("version %q", d.Version)
	}
	current := image("a")
	current.Version = "v0.4.0"
	if d := Compare(current, current, Options{Version: "v0.4.0"}); len(d.Notes) != 0 {
		t.Errorf("reports of the running version need no note: %q", d.Notes)
	}
}

func TestTooManyBuilds(t *testing.T) {
	var many []verdict.PHP
	for i := 0; i <= maxBuilds; i++ {
		many = append(many, build("php", fmt.Sprintf("8.4.%d", i), "cli", verdict.Fixed))
	}
	d := Compare(image("a", many...), image("b"), Options{})
	if len(d.PHP) != maxBuilds || !strings.Contains(strings.Join(d.Notes, " "), "only the first 1000") {
		t.Errorf("%d builds, notes %q", len(d.PHP), d.Notes)
	}
}

func fixedByRebuild() Diff {
	before := image("php:8.4.26-apache",
		build("libphp", "8.4.26", "apache-module", verdict.Vulnerable),
		build("php-cli", "8.4.26", "cli", verdict.Vulnerable))
	before.Image.ManifestDigest = "sha256:6985ff1ba36e5fda4a3257bef73c30b04ba657c29cf9cbaafc3f4d4ea0268a51"
	before.Image.Created = "2026-10-01T08:12:00Z"
	before.Distro = verdict.Distro{ID: "debian", Version: "13"}
	before.Notes = []string{"session.upload_progress.enabled is on by default in this image."}
	after := image("php:8.4.27-apache",
		build("libphp", "8.4.27", "apache-module", verdict.Fixed),
		build("php-cli", "8.4.27", "cli", verdict.Fixed),
		build("php-fpm", "8.4.27", "fpm", verdict.Fixed))
	after.Image.ManifestDigest = "sha256:9e41c7d2a0b8f3e5d6c7b8a9f0e1d2c3b4a5968778695a4b3c2d1e0f9a8b7c6d"
	after.Image.Created = "2026-10-22T03:10:00Z"
	after.Distro = verdict.Distro{ID: "debian", Version: "13"}
	after.Notes = []string{"session.upload_progress.enabled is on by default in this image. Until PHP fixes CVE-2026-115560, turn it off server-wide."}
	return Compare(before, after, Options{})
}

func TestTable(t *testing.T) {
	var buf bytes.Buffer
	if err := Table(&buf, fixedByRebuild()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	lines := strings.Split(out, "\n")
	if fields := strings.Fields(lines[0]); !reflect.DeepEqual(fields, []string{"BEFORE", "AFTER"}) {
		t.Errorf("header: %q", lines[0])
	}
	for _, want := range [][]string{
		{"Image", "php:8.4.26-apache", "php:8.4.27-apache"},
		{"Digest", "sha256:6985ff1ba36e…", "sha256:9e41c7d2a0b8…"},
		{"Created", "2026-10-01T08:12:00Z", "2026-10-22T03:10:00Z"},
		{"Distro", "debian", "13", "debian", "13"},
		{cve1, "VULNERABLE", "FIXED"},
		{cve2, "VULNERABLE", "FIXED"},
		{"session.upload_progress.enabled", "on", "on"},
		{"Action", "ACTION", "NEEDED", "OK"},
	} {
		found := false
		for _, l := range lines {
			found = found || reflect.DeepEqual(strings.Fields(l), want)
		}
		if !found {
			t.Errorf("no row %q:\n%s", want, out)
		}
	}
	for _, want := range []string{
		"PHP builds:\n" +
			"  changed    libphp 8.4.26 → 8.4.27 (apache-module)\n" +
			"    CVE-2026-109618, CVE-2026-109619: VULNERABLE → FIXED\n" +
			"  changed    php-cli 8.4.26 → 8.4.27 (cli)\n" +
			"    CVE-2026-109618, CVE-2026-109619: VULNERABLE → FIXED\n" +
			"  added      php-fpm 8.4.27 (fpm)\n" +
			"    CVE-2026-109618, CVE-2026-109619: FIXED\n",
		"Notes on the after image:\n  - session.upload_progress.enabled is on by default in this image. Until PHP fixes CVE-2026-115560, turn it off server-wide.\n",
		"\nResult: Fixed by this change: ACTION NEEDED → OK (exit 0)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "is on by default in this image.\n") {
		t.Errorf("the before image's notes don't belong in the table:\n%s", out)
	}
}

func TestTableShowsEveryKindOfChange(t *testing.T) {
	before := image("app:1", build("libapache2-mod-php8.2", "8.2.29-1~deb12u1", "apache-module", verdict.Vulnerable),
		build("php8.2-cgi", "8.2.29-1~deb12u1", "cgi", verdict.Vulnerable), build("php8.2-fpm", "8.2.29-1~deb12u1", "fpm", verdict.Vulnerable))
	after := image("app:2", build("libphp", "8.4.27", "apache-module", verdict.Fixed), build("php8.4-fpm", "8.4.27-1", "fpm", verdict.Fixed))
	var buf bytes.Buffer
	if err := Table(&buf, Compare(before, after, Options{})); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"  changed    php8.2-fpm 8.2.29-1~deb12u1 → php8.4-fpm 8.4.27-1 (fpm)\n",
		"  changed    libapache2-mod-php8.2 8.2.29-1~deb12u1 → libphp 8.4.27 (apache-module, matched by SAPI)\n",
		"  removed    php8.2-cgi 8.2.29-1~deb12u1 (cgi)\n    CVE-2026-109618, CVE-2026-109619: VULNERABLE\n",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("table lacks %q:\n%s", want, buf.String())
		}
	}

	buf.Reset()
	if err := Table(&buf, Compare(image("a"), image("b"), Options{})); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"No PHP found in either image.", "Result: No PHP change: NO PHP before and after (exit 0)"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("table lacks %q:\n%s", want, buf.String())
		}
	}
	if strings.Contains(buf.String(), "CVE-") || strings.Contains(buf.String(), phpini.UploadProgress) {
		t.Errorf("no PHP, so no verdicts or settings:\n%s", buf.String())
	}
}

// assertSafeForCI fails when a line of text output could be read as a workflow command:
// "::" after leading white space, or "##[" anywhere.
func assertSafeForCI(t *testing.T, out string) {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimLeftFunc(l, unicode.IsSpace), "::") || strings.Contains(l, "##[") {
			t.Fatalf("line holds a workflow command: %q", l)
		}
	}
}

func TestTableIsSafeForCILogs(t *testing.T) {
	evil := build("::warning::x", "8.4.26\n::error::y", "##[group]", "::set-output name=x::y")
	evil.CVEs[" ::debug::z"] = verdict.CVEResult{Verdict: "#"}
	before := image("::warning::before", evil)
	before.Verdicts["::error::cve"] = "##[add-mask]"
	before.Image.Created = "#"
	after := image("after", build("#", "#[x", "#", verdict.Fixed))
	after.Image.Created = "#[x"
	after.Notes = []string{"::error::note", "a\n::warning::b"}
	after.Settings[phpini.UploadProgress] = phpini.Setting{Effective: "\n::error::x"}
	var buf bytes.Buffer
	if err := Table(&buf, Compare(before, after, Options{})); err != nil {
		t.Fatal(err)
	}
	assertSafeForCI(t, buf.String())
}

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, fixedByRebuild()); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Tool, Outcome, Summary string
		Before, After          struct{ Name, Digest, Created string }
		Action                 map[string]string
		Verdicts               map[string]map[string]string
		UploadProgress         map[string]string
		PHP                    []struct {
			Change, Match string
			Before        *struct{ Name, Version, SAPI string }
			After         *struct{ Name, Version, SAPI string }
			CVEs          map[string]map[string]string
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Tool != "whichphp" || got.Outcome != "FIXED" || got.Summary != "Fixed by this change" ||
		got.Before.Name != "php:8.4.26-apache" || got.After.Digest != "sha256:9e41c7d2a0b8f3e5d6c7b8a9f0e1d2c3b4a5968778695a4b3c2d1e0f9a8b7c6d" ||
		got.Action["before"] != "ACTION_NEEDED" || got.Action["after"] != "OK" ||
		got.Verdicts[cve1]["after"] != "FIXED" || got.UploadProgress["after"] != "on" {
		t.Errorf("summary fields: %+v\n%s", got, buf.String())
	}
	if len(got.PHP) != 3 || got.PHP[0].Change != "changed" || got.PHP[0].Match != "name" || got.PHP[0].Before.Version != "8.4.26" ||
		got.PHP[0].After.SAPI != "apache-module" || got.PHP[0].CVEs[cve2]["before"] != "VULNERABLE" {
		t.Errorf("builds: %+v", got.PHP)
	}
	if added := got.PHP[2]; added.Change != "added" || added.Before != nil || added.Match != "" {
		t.Errorf("an added build has no before and no match: %+v", added)
	}

	// Without PHP, the lists are empty rather than null.
	buf.Reset()
	if err := JSON(&buf, Compare(image("a"), image("b"), Options{})); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"php": []`) || !strings.Contains(buf.String(), `"verdicts": {}`) {
		t.Errorf("empty lists:\n%s", buf.String())
	}
}

// A fix that rests on an unconfirmed distro backport is marked as such, and isn't
// called fixed.
func TestUnconfirmedBackport(t *testing.T) {
	before := image("app:1", distro("php8.3-fpm", "8.3.6-0ubuntu0.24.04.12", "fpm", "", verdict.Vulnerable))
	after := image("app:2", backport("php8.3-fpm", "8.3.6-0ubuntu0.24.04.13", "fpm", true))
	d := Compare(before, after, Options{})
	if d.Outcome != Improved || d.ExitCode() != 0 {
		t.Errorf("outcome %s, exit %d", d.Outcome, d.ExitCode())
	}
	if c := d.Verdicts[cve1]; c.Unconfirmed == nil || c.Unconfirmed.Before || !c.Unconfirmed.After {
		t.Errorf("image verdict: %+v", c)
	}
	if c := d.PHP[0].CVEs[cve2]; c.Unconfirmed == nil || !c.Unconfirmed.After {
		t.Errorf("build verdict: %+v", c)
	}
	var buf bytes.Buffer
	if err := Table(&buf, d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"    CVE-2026-109618, CVE-2026-109619: VULNERABLE → FIXED_BY_DISTRO_BACKPORT (unconfirmed)\n",
		"Result: Better, but not proven fixed: ACTION NEEDED → OK (exit 0)\n",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("table lacks %q:\n%s", want, buf.String())
		}
	}
	found := false
	for _, l := range strings.Split(buf.String(), "\n") {
		found = found || reflect.DeepEqual(strings.Fields(l), []string{cve1, "VULNERABLE", "FIXED_BY_DISTRO_BACKPORT", "(unconfirmed)"})
	}
	if !found {
		t.Errorf("no unconfirmed verdict row:\n%s", buf.String())
	}
	buf.Reset()
	if err := JSON(&buf, d); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Verdicts map[string]VerdictChange
		PHP      []struct{ CVEs map[string]VerdictChange }
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if u := got.Verdicts[cve1].Unconfirmed; u == nil || u.Before || !u.After || !strings.Contains(buf.String(), `"unconfirmed": {`) {
		t.Errorf("JSON:\n%s", buf.String())
	}
	if u := got.PHP[0].CVEs[cve1].Unconfirmed; u == nil || !u.After {
		t.Errorf("JSON builds:\n%s", buf.String())
	}

	// A confirmed backport carries no mark.
	d = Compare(before, image("app:2", backport("php8.3-fpm", "8.3.6-0ubuntu0.24.04.13", "fpm", false)), Options{})
	buf.Reset()
	if err := JSON(&buf, d); err != nil || d.Outcome != Fixed || strings.Contains(buf.String(), "unconfirmed") {
		t.Errorf("confirmed: %s, %v\n%s", d.Outcome, err, buf.String())
	}
}

// Without PHP in the after image, nothing is proven fixed.
func TestNoPHPAfter(t *testing.T) {
	d := Compare(image("app:1", build("libphp", "8.4.26", "apache-module", verdict.Vulnerable)), image("app:2"), Options{})
	var buf bytes.Buffer
	if err := Table(&buf, d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"  removed    libphp 8.4.26 (apache-module)\n",
		"Result: No PHP found in the after image, which isn't proof of a fix: ACTION NEEDED → NO PHP (exit 0)\n",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("table lacks %q:\n%s", want, buf.String())
		}
	}
	if strings.Contains(buf.String(), "Fixed") {
		t.Errorf("no PHP isn't a fix:\n%s", buf.String())
	}
}
