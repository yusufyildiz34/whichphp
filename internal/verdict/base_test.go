package verdict

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yusufyildiz34/whichphp/internal/syftjson"
)

func config(env ...string) *syftjson.ImageConfig {
	c := &syftjson.ImageConfig{}
	c.Config.Env = env
	return c
}

var officialEnv = []string{
	"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	"PHP_INI_DIR=/usr/local/etc/php",
	"PHP_VERSION=8.4.26",
	"PHP_URL=https://www.php.net/distributions/php-8.4.26.tar.xz",
}

func TestFindBase(t *testing.T) {
	trixie := syftjson.Distro{ID: "debian", VersionID: "13.7"}
	fpm := []PHP{{Name: "php-fpm", Paths: []string{"/usr/local/sbin/php-fpm"}}}
	cases := []struct {
		name   string
		cfg    *syftjson.ImageConfig
		distro syftjson.Distro
		php    []PHP
		want   string // image:tag, or "" for none
	}{
		{"apache variant", config(append(officialEnv, "APACHE_CONFDIR=/etc/apache2")...), trixie, nil, "php:8.4.26-apache-trixie"},
		{"fpm variant on Alpine", config(officialEnv...), syftjson.Distro{ID: "alpine", VersionID: "3.24.3"}, fpm, "php:8.4.26-fpm-alpine3.24"},
		// cli and zts look alike from the outside; no tag is better than a wrong one.
		{"variant not shown", config(officialEnv...), trixie, nil, "php:"},
		{"not php.net's download", config("PHP_INI_DIR=/usr/local/etc/php", "PHP_VERSION=8.4.26", "PHP_URL=https://example.org/php.tar.xz"), trixie, nil, ""},
		{"not the official layout", config("PHP_INI_DIR=/etc/php", "PHP_VERSION=8.4.26", "PHP_URL=https://www.php.net/distributions/php-8.4.26.tar.xz"), trixie, nil, ""},
		{"not a version", config("PHP_INI_DIR=/usr/local/etc/php", "PHP_VERSION=latest", "PHP_URL=https://www.php.net/distributions/x"), trixie, nil, ""},
		{"the last setting wins", config(append(officialEnv, "APACHE_CONFDIR=/etc/apache2", "PHP_VERSION=8.4.27")...), trixie, nil, "php:8.4.27-apache-trixie"},
		{"Bitnami", config("BITNAMI_APP_NAME=php-fpm", "APP_VERSION=8.2.26"), syftjson.Distro{ID: "debian", VersionID: "12.8"}, nil, "bitnami/php-fpm:8.2.26"},
		{"a Bitnami app, not its PHP", config("BITNAMI_APP_NAME=wordpress", "APP_VERSION=6.8.3"), trixie, nil, ""},
		{"no config", nil, trixie, nil, ""},
	}
	for _, c := range cases {
		b := findBase(c.cfg, c.distro, c.php)
		got := ""
		if b != nil {
			got = b.Image + ":" + b.Tag
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestBaseAdvice(t *testing.T) {
	cli := func(version string, v Verdict) PHP {
		return PHP{Name: "php-cli", Version: version, Source: SourceUpstream, Paths: []string{"/usr/local/bin/php"},
			CVEs: map[string]CVEResult{cve18: {Verdict: v}, cve19: {Verdict: v}}}
	}
	debianPHP := PHP{Name: "php8.4-cli", Version: "8.4.16-1", Source: SourceDistro, Paths: []string{"/var/lib/dpkg/status"},
		CVEs: map[string]CVEResult{cve19: {Verdict: Vulnerable}}}
	cases := []struct {
		name string
		base *BaseImage
		php  []PHP
		want string
	}{
		{"supported branch", &BaseImage{Image: "php", PHPVersion: "8.4.26", Variant: "apache", OS: "trixie"}, []PHP{cli("8.4.26", Vulnerable)},
			"Rebuild it on the current php:8.4-apache, which has 8.4.27 or later"},
		// The official image stopped building bullseye before the fix; the floating tag got it.
		{"an old Debian release", &BaseImage{Image: "php", PHPVersion: "8.2.20", Variant: "fpm", OS: "bullseye"}, []PHP{cli("8.2.20", Vulnerable)},
			"the current php:8.2-fpm, which has 8.2.35"},
		{"Alpine", &BaseImage{Image: "php", PHPVersion: "8.3.35", Variant: "fpm", OS: "alpine3.18"}, []PHP{cli("8.3.35", Vulnerable)},
			"the current php:8.3-fpm-alpine, which has 8.3.36"},
		{"variant not shown", &BaseImage{Image: "php", PHPVersion: "8.3.35"}, []PHP{cli("8.3.35", Vulnerable)},
			"a current php:8.3 image of the same variant (cli or zts), which has 8.3.36"},
		{"end-of-life branch", &BaseImage{Image: "php", PHPVersion: "8.1.34", Variant: "fpm"}, []PHP{cli("8.1.34", VulnerableEOL)}, "PHP 8.1 gets no upstream fix"},
		{"base already fixed", &BaseImage{Image: "php", PHPVersion: "8.4.27", Variant: "apache"}, []PHP{cli("8.4.27", Fixed)}, ""},
		// The base's PHP was replaced by a fixed one; a vulnerable distro package elsewhere in
		// the image isn't fixed by a new base.
		{"base PHP replaced", &BaseImage{Image: "php", PHPVersion: "8.4.26", Variant: "apache"}, []PHP{cli("8.4.27", Fixed), debianPHP}, ""},
		{"no PHP left from the base", &BaseImage{Image: "php", PHPVersion: "8.4.26"}, []PHP{debianPHP}, ""},
		// A pre-release base isn't an end-of-life branch.
		{"pre-release branch", &BaseImage{Image: "php", PHPVersion: "8.6.0RC2"}, []PHP{cli("8.6.0RC2", Vulnerable)}, ""},
		{"Bitnami", &BaseImage{Image: "bitnami/php-fpm", PHPVersion: "8.2.26"}, []PHP{cli("8.2.26", Vulnerable)}, ""},
		{"no base", nil, []PHP{cli("8.4.26", Vulnerable)}, ""},
	}
	for _, c := range cases {
		got := baseAdvice(c.base, c.php)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: got %q, want it to contain %q", c.name, got, c.want)
		}
	}
}

// The base shows in the report, and its advice in the notes.
func TestBaseInReport(t *testing.T) {
	d := doc(t, "debian", "13.7", "2026-10-01T00:00:00Z", nil, official("8.4.26"))
	cfg, _ := json.Marshal(map[string]any{"created": "2026-10-01T00:00:00Z",
		"config": map[string]any{"Env": append(officialEnv, "APACHE_CONFDIR=/etc/apache2")}})
	d.Source.Metadata, _ = json.Marshal(map[string]any{"userInput": "example:test", "config": cfg})
	r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now})
	if r.Image.Base == nil || r.Image.Base.Tag != "8.4.26-apache-trixie" {
		t.Fatalf("base %+v", r.Image.Base)
	}
	found := false
	for _, n := range r.Notes {
		found = found || strings.Contains(n, "php:8.4-apache,")
	}
	if !found {
		t.Fatalf("notes %q", r.Notes)
	}
}
