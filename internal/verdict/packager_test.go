package verdict

import (
	"strings"
	"testing"

	"github.com/yusufyildiz34/whichphp/internal/advisory"
	"github.com/yusufyildiz34/whichphp/internal/grypejson"
)

// withBackports swaps in synthetic packagers.csv rows, so these tests check the rules
// whatever the real data says.
func withBackports(t *testing.T, rows string) {
	t.Helper()
	bs, err := advisory.ParseBackports([]byte("packager,branch,distro,fixed,cves,source\n" + rows))
	if err != nil {
		t.Fatal(err)
	}
	saved := advisory.Backports
	advisory.Backports = bs
	t.Cleanup(func() { advisory.Backports = saved })
}

const synthetic = `Remi,7.4,,7.4.33-31,CVE-2026-109618 CVE-2026-109619,https://example.org/remi-74
Remi,7.3,,none,,https://example.org/remi-73
Sury,8.0,,1:8.0.30-25,CVE-2026-109618 CVE-2026-109619,https://example.org/sury-80
Sury,7.4,,1:7.4.33-31,CVE-2026-109619,https://example.org/sury-74
Freexian ELTS,7.3,debian 10,7.3.31-1~deb10u12,CVE-2026-109618 CVE-2026-109619,https://example.org/ela
`

func remi74(release string) art {
	v := "7.4.33-" + release + ".el9.remi"
	return art{"php74-php-cli", v, "rpm", "pkg:rpm/redhat/php74-php-cli@" + v, "", "/var/lib/rpm/rpmdb.sqlite"}
}

func TestPackagerBackport(t *testing.T) {
	withBackports(t, synthetic)
	cases := []struct {
		name   string
		distro string
		a      art
		cve    string
		want   Verdict
		why    string
	}{
		{"Remi at the fixed release", "rhel 9.6", remi74("31"), cve18, FixedByVendorBackport, "example.org/remi-74"},
		{"Remi above the fixed release", "rhel 9.6", remi74("32"), cve19, FixedByVendorBackport, "backported"},
		{"Remi below the fixed release", "rhel 9.6", remi74("30"), cve18, Vulnerable, "7.4.33-31"},
		{"Remi branch with no fix", "rhel 9.6",
			art{"php73-php-fpm", "7.3.33-18.el9.remi", "rpm", "", "", "/var/lib/rpm/rpmdb.sqlite"}, cve18, VulnerableEOL, "published no fix"},
		{"Remi branch with no data", "rhel 9.6",
			art{"php72-php-cli", "7.2.34-20.el9.remi", "rpm", "", "", "/var/lib/rpm/rpmdb.sqlite"}, cve19, NeedsVendorConfirmation, "changelog"},
		{"Sury with the epoch", "debian 12.12",
			art{"php8.0-fpm", "1:8.0.30-25+0~20261021.88+debian12~1.gbpabebea", "deb", "", "", "/var/lib/dpkg/status"}, cve18, FixedByVendorBackport, ""},
		{"Sury's temporary arm build", "debian 12.12",
			art{"php8.0-cli", "1:8.0.30-25+freexian12.1+php+1", "deb", "", "", "/var/lib/dpkg/status"}, cve18, FixedByVendorBackport, ""},
		{"Sury without the epoch sorts below it", "debian 12.12",
			art{"php8.0-fpm", "8.0.30-26+deb.sury.org+1", "deb", "", "", "/var/lib/dpkg/status"}, cve18, Vulnerable, ""},
		{"Sury row for one CVE only, the CVE it fixes", "ubuntu 24.04",
			art{"php7.4-cli", "1:7.4.33-31+ubuntu24.04.1+deb.sury.org+1", "deb", "", "", "/var/lib/dpkg/status"}, cve19, FixedByVendorBackport, ""},
		{"Sury row for one CVE only, the other CVE", "ubuntu 24.04",
			art{"php7.4-cli", "1:7.4.33-31+ubuntu24.04.1+deb.sury.org+1", "deb", "", "", "/var/lib/dpkg/status"}, cve18, NeedsVendorConfirmation, ""},
		// A higher epoch than the row's means another line of builds, or a row missing its
		// epoch: never ordered above the row.
		{"higher epoch than the row", "rhel 9.6",
			art{"php74-php-cli", "1:7.4.33-5.el9.remi", "rpm", "", "", "/var/lib/rpm/rpmdb.sqlite"}, cve19, NeedsVendorConfirmation, ""},
		{"Remi supported branch ships upstream", "rhel 9.6",
			art{"php-cli", "8.3.36-1.el9.remi", "rpm", "", "", "/var/lib/rpm/rpmdb.sqlite"}, cve18, Fixed, ""},
		{"Remi supported branch before the fix", "rhel 9.6",
			art{"php-cli", "8.3.35-1.el9.remi", "rpm", "", "", "/var/lib/rpm/rpmdb.sqlite"}, cve18, Vulnerable, "upstream"},
	}
	for _, c := range cases {
		id, ver, _ := strings.Cut(c.distro, " ")
		d := doc(t, id, ver, "2026-10-25T00:00:00Z", nil, c.a)
		r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now})
		if len(r.PHP) != 1 || r.PHP[0].Source != SourceThirdParty {
			t.Errorf("%s: found %+v, want one third-party build", c.name, r.PHP)
			continue
		}
		res := r.PHP[0].CVEs[c.cve]
		if res.Verdict != c.want || !strings.Contains(res.Why, c.why) {
			t.Errorf("%s: %s = %s (%s), want %s mentioning %q", c.name, c.cve, res.Verdict, res.Why, c.want, c.why)
		}
	}
}

// Freexian's Extended LTS builds look like Debian's own; only a version at or above the
// one in its advisory shows the package came from it.
func TestExtendedLTSBackport(t *testing.T) {
	withBackports(t, synthetic)
	cli := func(v string) art { return art{"php7.3-cli", v, "deb", "", "", "/var/lib/dpkg/status"} }
	cases := []struct {
		name    string
		release string
		a       art
		want    Verdict
		why     string
	}{
		{"ELTS build", "10.13", cli("7.3.31-1~deb10u12"), FixedByVendorBackport, "Freexian ELTS"},
		{"later ELTS build", "10.13", cli("7.3.31-1~deb10u13"), FixedByVendorBackport, ""},
		{"Debian's last LTS build", "10.13", cli("7.3.31-1~deb10u7"), VulnerableEOL, "first build with the fix"},
		{"the row is for Debian 10 only", "11.11", cli("7.3.31-1~deb10u12"), VulnerableEOL, ""},
		// An unrecognized repository's build that sorts above the row isn't Freexian's.
		{"another numbering", "10.13", cli("1:7.3.33-30+other1"), VulnerableEOL, ""},
	}
	for _, c := range cases {
		d := doc(t, "debian", c.release, "2021-03-01T00:00:00Z", nil, c.a)
		r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now})
		res := r.PHP[0].CVEs[cve18]
		if r.PHP[0].Source != SourceDistro || res.Verdict != c.want || !strings.Contains(res.Why, c.why) {
			t.Errorf("%s: %s %s = %s (%s), want %s mentioning %q", c.name, r.PHP[0].Source, cve18, res.Verdict, res.Why, c.want, c.why)
		}
	}
}

// cPanel's EasyApache 4 builds, against the rows in packagers.csv. Versions are from
// cPanel's repository metadata (October 2026).
func TestCPanelBuilds(t *testing.T) {
	rpm := func(name, v string) art { return art{name, v, "rpm", "", "", "/var/lib/rpm/rpmdb.sqlite"} }
	deb := func(name, v string) art { return art{name, v, "deb", "", "", "/var/lib/dpkg/status"} }
	cases := []struct {
		name     string
		distro   string
		a        art
		want     Verdict
		provider string
		sapi     string
	}{
		{"ea-php81 backport", "almalinux 9.6", rpm("ea-php81-php-fpm", "8.1.34-5.12.1.cpanel"), FixedByVendorBackport, "cPanel", "fpm"},
		{"ea-php81 before the backport", "almalinux 9.6", rpm("ea-php81-php-cli", "8.1.34-4.11.9.cpanel"), Vulnerable, "cPanel", "cli"},
		{"ea-php81 on Ubuntu", "ubuntu 24.04", deb("ea-php81-php-cli", "8.1.34-5+12.1.cpanel"), FixedByVendorBackport, "cPanel", "cli"},
		{"ea-php80 rebuild", "almalinux 8.10", rpm("ea-php80-php-litespeed", "8.0.30-12.20.2.cpanel"), FixedByVendorBackport, "cPanel", "litespeed"},
		{"ea-php74 Apache module", "centos 7.9", rpm("ea-php74-php", "7.4.33-19.26.1.cpanel"), FixedByVendorBackport, "cPanel", "apache-module"},
		{"ea-php74 before the backport", "almalinux 8.10", rpm("ea-php74-php-fpm", "7.4.33-18.24.9.cpanel"), Vulnerable, "cPanel", "fpm"},
		// Rebuilt on October 27 with no code change; the "none" row decides.
		{"ea-php73 has no fix", "centos 7.9", rpm("ea-php73-php-fpm", "7.3.33-15.20.31.cpanel"), VulnerableEOL, "cPanel", "fpm"},
		{"ea-php83 ships upstream", "almalinux 9.6", rpm("ea-php83-php-fpm", "8.3.36-1.1.1.cpanel"), Fixed, "cPanel", "fpm"},
		{"ea-php84 before the upstream fix", "almalinux 9.6", rpm("ea-php84-php-fpm", "8.4.26-2.4.2.cpanel"), Vulnerable, "cPanel", "fpm"},
		// CloudLinux's build under the same name: never compared with cPanel's rows.
		{"CloudLinux's ea-php81", "cloudlinux 8.10", rpm("ea-php81-php-fpm", "1:8.1.34-4.el8.cloudlinux.2"), FixedByVendorBackport, "CloudLinux ea-php", "fpm"},
		{"CloudLinux's ea-php73", "cloudlinux 8.10", rpm("ea-php73-php-fpm", "1:7.3.33-15.el8.cloudlinux.17"), Vulnerable, "CloudLinux ea-php", "fpm"},
	}
	for _, c := range cases {
		id, ver, _ := strings.Cut(c.distro, " ")
		d := doc(t, id, ver, "2026-10-25T00:00:00Z", nil, c.a)
		r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now})
		if len(r.PHP) != 1 {
			t.Errorf("%s: found %d PHP builds, want 1", c.name, len(r.PHP))
			continue
		}
		p := r.PHP[0]
		if p.Provider != c.provider || p.SAPI != c.sapi || p.CVEs[cve19].Verdict != c.want {
			t.Errorf("%s: %s %s %s = %s (%s), want %s %s %s", c.name, p.Provider, p.SAPI, cve19, p.CVEs[cve19].Verdict, p.CVEs[cve19].Why, c.provider, c.sapi, c.want)
		}
	}
}

// Packages that only pull PHP in or dispatch to it, and ea-phpNN-php on 8.x, which is
// empty, aren't PHP builds.
func TestCPanelMetaPackagesAreNotPHP(t *testing.T) {
	var arts []art
	for _, n := range []string{"ea-php81", "ea-php81-php", "ea-php81-runtime", "ea-php-cli", "ea-php-cli-lsphp", "ea-php81-php-common"} {
		arts = append(arts, art{n, "8.1.34-2.6.1.cpanel", "rpm", "", "", "/var/lib/rpm/rpmdb.sqlite"})
	}
	d := doc(t, "almalinux", "9.6", "2026-10-25T00:00:00Z", nil, arts...)
	if r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now}); len(r.PHP) != 0 {
		t.Fatalf("found %+v", r.PHP)
	}
}

// Sury's builds of end-of-life branches, against the rows in packagers.csv. Versions
// are from packages.sury.org and Launchpad (October 2026).
func TestSuryBuilds(t *testing.T) {
	deb := func(name, v string) art { return art{name, v, "deb", "", "", "/var/lib/dpkg/status"} }
	cases := []struct {
		name   string
		distro string
		a      art
		cve    string
		want   Verdict
	}{
		{"8.1 on packages.sury.org", "debian 12.12", deb("php8.1-fpm", "8.1.34-9+0~20261021.82+debian12~1.gbp4e430a"), cve18, FixedByVendorBackport},
		{"8.1 on Launchpad", "ubuntu 24.04", deb("php8.1-fpm", "8.1.34-9+ubuntu24.04.1+deb.sury.org+1"), cve18, FixedByVendorBackport},
		{"8.1 before the fix", "ubuntu 24.04", deb("php8.1-fpm", "8.1.34-8+ubuntu24.04.1+deb.sury.org+1"), cve18, Vulnerable},
		{"7.4 with its epoch", "debian 12.12", deb("libapache2-mod-php7.4", "1:7.4.33-31+0~20261021.121+debian12~1.gbpe9c428"), cve19, FixedByVendorBackport},
		{"7.4 one build earlier", "debian 12.12", deb("php7.4-fpm", "1:7.4.33-30+0~20260703.115+debian12~1.gbp5d1e2f"), cve19, Vulnerable},
		{"7.4 temporary arm build", "debian 12.12", deb("php7.4-cli", "1:7.4.33-31+freexian12.1+php+1"), cve19, FixedByVendorBackport},
		// -80 named the CVEs but left part of the fix out; only -81 is fixed.
		{"7.1 first build", "ubuntu 22.04", deb("php7.1-fpm", "7.1.33-80+ubuntu22.04.1+deb.sury.org+1"), cve19, Vulnerable},
		{"7.1 complete build", "debian 13.1", deb("php7.1-fpm", "7.1.33-81+0~20261022.128+debian13~1.gbpa88ccf"), cve19, FixedByVendorBackport},
		{"5.6 is older than CVE-2026-109618", "debian 12.12", deb("php5.6-cli", "5.6.40-104+0~20261021.99+debian12~1.gbp1a2b3c"), cve18, NotAffected},
		{"8.3 ships upstream", "debian 12.12", deb("php8.3-fpm", "8.3.36-1+0~20261021.40+debian12~1.gbp9f8e7d"), cve18, Fixed},
	}
	for _, c := range cases {
		id, ver, _ := strings.Cut(c.distro, " ")
		d := doc(t, id, ver, "2026-10-25T00:00:00Z", nil, c.a)
		r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now})
		p := r.PHP[0]
		if p.Provider != "Sury" || p.CVEs[c.cve].Verdict != c.want {
			t.Errorf("%s: %s %s = %s (%s), want Sury %s", c.name, p.Provider, c.cve, p.CVEs[c.cve].Verdict, p.CVEs[c.cve].Why, c.want)
		}
	}
}

// Freexian's Extended LTS builds, against the rows in packagers.csv.
func TestFreexianELTSBuilds(t *testing.T) {
	cases := []struct {
		name    string
		release string
		a       art
		want    Verdict
	}{
		{"bullseye ELTS", "11.11", art{"php7.4-fpm", "7.4.33-1+deb11u14", "deb", "", "", "/var/lib/dpkg/status"}, FixedByVendorBackport},
		{"bullseye's last Debian LTS build", "11.11", art{"php7.4-fpm", "7.4.33-1+deb11u12", "deb", "", "", "/var/lib/dpkg/status"}, VulnerableEOL},
		{"buster ELTS", "10.13", art{"libapache2-mod-php7.3", "7.3.31-1~deb10u16", "deb", "", "", "/var/lib/dpkg/status"}, FixedByVendorBackport},
		{"buster ELTS before PHP2Shell", "10.13", art{"php7.3-cli", "7.3.31-1~deb10u15", "deb", "", "", "/var/lib/dpkg/status"}, VulnerableEOL},
		{"stretch ELTS", "9.13", art{"php7.0-fpm", "7.0.33-0+deb9u26", "deb", "", "", "/var/lib/dpkg/status"}, FixedByVendorBackport},
	}
	for _, c := range cases {
		d := doc(t, "debian", c.release, "2026-10-25T00:00:00Z", nil, c.a)
		r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now})
		if res := r.PHP[0].CVEs[cve19]; res.Verdict != c.want {
			t.Errorf("%s: %s = %s (%s), want %s", c.name, cve19, res.Verdict, res.Why, c.want)
		}
	}
}

// Remi's builds, against the rows in packagers.csv. Versions are from Remi's repository
// (October 2026).
func TestRemiBuilds(t *testing.T) {
	rpm := func(name, v string) art { return art{name, v, "rpm", "", "", "/var/lib/rpm/rpmdb.sqlite"} }
	cases := []struct {
		name   string
		distro string
		a      art
		want   Verdict
	}{
		{"7.4 module", "almalinux 9.6", rpm("php-fpm", "7.4.33-31.module_php.7.4.el9.remi"), FixedByVendorBackport},
		{"7.4 module before the fix", "almalinux 9.6", rpm("php-fpm", "7.4.33-30.module_php.7.4.el9.remi"), Vulnerable},
		{"8.1 collection", "rocky 10.0", rpm("php81-php-fpm", "8.1.34-6.el10.remi"), FixedByVendorBackport},
		{"8.0 on Fedora", "fedora 43", rpm("php80-php-cli", "8.0.30-21.fc43.remi"), FixedByVendorBackport},
		{"8.0 one build earlier", "almalinux 8.10", rpm("php-cli", "8.0.30-20.module_php.8.0.el8.remi"), Vulnerable},
		// -23 named the CVEs but missed part of the patch.
		{"7.3 first build", "almalinux 8.10", rpm("php73-php-fpm", "7.3.33-23.el8.remi"), Vulnerable},
		{"7.3 rebuilt with the whole patch", "almalinux 8.10", rpm("php73-php-fpm", "7.3.33-24.el8.remi"), FixedByVendorBackport},
		{"EL7's last build", "centos 7.9", rpm("php74-php-cli", "7.4.33-15.el7.remi"), Vulnerable},
		{"5.6 collection has no fix", "almalinux 8.10", rpm("php56-php-fpm", "5.6.40-47.el8.remi"), VulnerableEOL},
		{"8.3 ships upstream", "almalinux 9.6", rpm("php-fpm", "8.3.36-1.module_php.8.3.el9.remi"), Fixed},
	}
	for _, c := range cases {
		id, ver, _ := strings.Cut(c.distro, " ")
		d := doc(t, id, ver, "2026-10-25T00:00:00Z", nil, c.a)
		r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now})
		p := r.PHP[0]
		if p.Provider != "Remi" || p.CVEs[cve19].Verdict != c.want {
			t.Errorf("%s: %s %s = %s (%s), want Remi %s", c.name, p.Provider, cve19, p.CVEs[cve19].Verdict, p.CVEs[cve19].Why, c.want)
		}
	}
}

// GetPageSpeed's builds look like CentOS's own but for the rpm Vendor tag. With no rows
// for it, an end-of-life branch needs the vendor's confirmation, and its upstream
// rebuilds of 8.2 and later go by version.
func TestGetPageSpeedBuilds(t *testing.T) {
	cases := []struct {
		a    art
		want Verdict
	}{
		{art{"php-fpm", "7.4.33-33.el7", "rpm", "", "", "/var/lib/rpm/Packages"}, NeedsVendorConfirmation},
		{art{"php81-php-cli", "8.1.34-7.el7", "rpm", "", "", "/var/lib/rpm/Packages"}, NeedsVendorConfirmation},
		{art{"php-cli", "8.3.36-2.el7", "rpm", "", "", "/var/lib/rpm/Packages"}, Fixed},
		{art{"php-cli", "8.3.35-1.el7", "rpm", "", "", "/var/lib/rpm/Packages"}, Vulnerable},
	}
	for _, c := range cases {
		d := doc(t, "centos", "7.9", "2026-10-25T00:00:00Z", nil, c.a)
		d.Artifacts[0].Metadata.Vendor = "GetPageSpeed LLC"
		r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now})
		p := r.PHP[0]
		if p.Provider != "GetPageSpeed" || p.CVEs[cve19].Verdict != c.want {
			t.Errorf("%s %s: %s %s = %s (%s), want GetPageSpeed %s", c.a.name, c.a.version, p.Provider, cve19, p.CVEs[cve19].Verdict, p.CVEs[cve19].Why, c.want)
		}
	}
}

// CloudLinux's builds, against the rows in packagers.csv. Versions are from CloudLinux's
// repository metadata (October 2026).
func TestCloudLinuxBuilds(t *testing.T) {
	rpm := func(name, v string) art { return art{name, v, "rpm", "", "", "/var/lib/rpm/rpmdb.sqlite"} }
	cases := []struct {
		name     string
		release  string
		a        art
		want     Verdict
		provider string
	}{
		{"alt-php74", "8.10", rpm("alt-php74-cli", "7.4.33-81.el8"), FixedByVendorBackport, "CloudLinux alt-php"},
		{"alt-php74 before the fix", "8.10", rpm("alt-php74-php-fpm", "7.4.33-80.el8"), Vulnerable, "CloudLinux alt-php"},
		{"alt-php74 under its old FPM name", "7.9", rpm("alt-php74-fpm", "7.4.33-35.el7"), Vulnerable, "CloudLinux alt-php"},
		{"alt-php73 with its epoch", "9.6", rpm("alt-php73-cli", "1:7.3.33-82.el9"), FixedByVendorBackport, "CloudLinux alt-php"},
		{"alt-php73 one build earlier", "9.6", rpm("alt-php73-cli", "1:7.3.33-81.el9"), Vulnerable, "CloudLinux alt-php"},
		{"alt-php85 backport below 8.5.12", "9.6", rpm("alt-php85-cli", "8.5.11-5.el9"), FixedByVendorBackport, "CloudLinux alt-php"},
		{"alt-php85 before the backport", "9.6", rpm("alt-php85-cli", "8.5.11-4.el9"), Vulnerable, "CloudLinux alt-php"},
		{"alt-php85 rebuilt as 8.5.12", "9.6", rpm("alt-php85-cli", "8.5.12-1.el9"), Fixed, "CloudLinux alt-php"},
		{"ea-php82 backport", "9.6", rpm("ea-php82-php-fpm", "1:8.2.34-2.el9.cloudlinux.1"), FixedByVendorBackport, "CloudLinux ea-php"},
		// Built on October 20, before the fix, with the same release up to the suffix.
		{"ea-php82 on October 20", "9.6", rpm("ea-php82-php-fpm", "1:8.2.34-2.el9.cloudlinux"), Vulnerable, "CloudLinux ea-php"},
		{"ea-php74 on EL10", "10.0", rpm("ea-php74-php-cli", "1:7.4.33-18.el10.cloudlinux.13"), FixedByVendorBackport, "CloudLinux ea-php"},
		{"ea-php74 one build earlier", "10.0", rpm("ea-php74-php-cli", "1:7.4.33-18.el10.cloudlinux.12"), Vulnerable, "CloudLinux ea-php"},
		{"ea-php without a dist tag", "9.6", rpm("ea-php80-php-cli", "1:8.0.30-11.cloudlinux.1"), NeedsVendorConfirmation, "CloudLinux ea-php"},
		{"system PHP", "9.6", rpm("php-cli", "1:8.1.32-1.module_el9.8.0+406+aadb97d2.cloudlinux.2"), NeedsVendorConfirmation, "CloudLinux"},
		{"system PHP rebased", "9.6", rpm("php-fpm", "1:8.3.36-1.module_el9.8.0+410+17f8e765.cloudlinux.1"), Fixed, "CloudLinux"},
	}
	for _, c := range cases {
		d := doc(t, "cloudlinux", c.release, "2026-10-25T00:00:00Z", nil, c.a)
		r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now})
		if len(r.PHP) != 1 {
			t.Errorf("%s: found %d PHP builds, want 1", c.name, len(r.PHP))
			continue
		}
		p := r.PHP[0]
		if p.Provider != c.provider || p.CVEs[cve19].Verdict != c.want {
			t.Errorf("%s: %s %s = %s (%s), want %s %s", c.name, p.Provider, cve19, p.CVEs[cve19].Verdict, p.CVEs[cve19].Why, c.provider, c.want)
		}
	}
	// alt-phpNN-common and the meta package carry no SAPI.
	d := doc(t, "cloudlinux", "8.10", "2026-10-25T00:00:00Z", nil, rpm("alt-php74-common", "7.4.33-81.el8"), rpm("alt-php74", "7.4.33-81.el8"))
	if r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now}); len(r.PHP) != 0 {
		t.Errorf("found %+v", r.PHP)
	}
}

// TuxCare's builds, against the rows in packagers.csv. Versions are from TuxCare's errata
// (October 2026).
func TestTuxCareBuilds(t *testing.T) {
	rpm := func(name, v string) art { return art{name, v, "rpm", "", "", "/var/lib/rpm/Packages"} }
	deb := func(name, v string) art { return art{name, v, "deb", "", "", "/var/lib/dpkg/status"} }
	cases := []struct {
		name     string
		distro   string
		a        art
		want     Verdict
		provider string
	}{
		{"CentOS 7", "centos 7", rpm("php-fpm", "5.4.16-48.el7.tuxcare.els21"), FixedByVendorBackport, "TuxCare"},
		{"CentOS 7 one build earlier", "centos 7", rpm("php-fpm", "5.4.16-48.el7.tuxcare.els20"), Vulnerable, "TuxCare"},
		// The same build is an unfixed August release on CloudLinux 7, fixed from els24.
		{"CloudLinux 7 els21", "cloudlinux 7.9", rpm("php-cli", "5.4.16-48.el7.tuxcare.els21"), Vulnerable, "TuxCare"},
		{"CloudLinux 7 els24", "cloudlinux 7.9", rpm("php-cli", "5.4.16-48.el7.tuxcare.els24"), FixedByVendorBackport, "TuxCare"},
		{"Amazon Linux 2", "amzn 2", rpm("php", "5.4.16-46.amzn2.0.7.tuxcare.els11"), FixedByVendorBackport, "TuxCare"},
		{"CentOS 8.5 stream", "centos 8", rpm("php-fpm", "7.4.19-1.module_el8.5.0+2709+673b459a.tuxcare.els32"), FixedByVendorBackport, "TuxCare"},
		// Above CentOS 8.4's fixed 7.4.6 build, but on another line.
		{"CentOS 8.5 one build earlier", "centos 8", rpm("php-fpm", "7.4.19-1.module_el8.5.0+2709+673b459a.tuxcare.els31"), Vulnerable, "TuxCare"},
		{"CentOS 8.4 stream", "centos 8", rpm("php-fpm", "7.4.6-4.module_el8.4.0+2710+d5314ff6.tuxcare.els33"), FixedByVendorBackport, "TuxCare"},
		// Above AlmaLinux 9.2's fixed 8.0.30-1 build, but on another line.
		{"AlmaLinux 9.6 one build earlier", "almalinux 9.6", rpm("php-cli", "8.0.30-3.el9_6.tuxcare.els9"), Vulnerable, "TuxCare"},
		{"AlmaLinux 9.6", "almalinux 9.6", rpm("php-cli", "8.0.30-3.el9_6.tuxcare.els10"), FixedByVendorBackport, "TuxCare"},
		{"a line with no row", "almalinux 9.2", rpm("php-cli", "8.1.14-1.module_el9.2.0+12+abcdef01.tuxcare.els3"), NeedsVendorConfirmation, "TuxCare"},
		{"Debian 11", "debian 11.11", deb("libapache2-mod-php7.4", "7.4.33-1+deb11u12+tuxcare.els2"), FixedByVendorBackport, "TuxCare"},
		{"Debian 11 one build earlier", "debian 11.11", deb("php7.4-fpm", "7.4.33-1+deb11u12+tuxcare.els1"), Vulnerable, "TuxCare"},
		{"Ubuntu 20.04", "ubuntu 20.04", deb("php7.4-cli", "7.4.3-4ubuntu2.29+tuxcare.els10"), FixedByVendorBackport, "TuxCare"},
		{"Alpine has no version order", "alpine 3.18.12", art{"php82-fpm", "8.2.16.tuxcare.els10-r0", "apk", "", "", "/lib/apk/db/installed"}, NeedsVendorConfirmation, "TuxCare"},
		{"alt-php on Ubuntu", "ubuntu 24.04", deb("alt-php74-cli", "7.4.33-81"), FixedByVendorBackport, "TuxCare alt-php"},
		{"alt-php on Ubuntu before the fix", "ubuntu 24.04", deb("alt-php74-php-fpm", "7.4.33-80"), Vulnerable, "TuxCare alt-php"},
		{"alt-php85 on Debian", "debian 12.12", deb("alt-php85-cli", "8.5.11-4"), FixedByVendorBackport, "TuxCare alt-php"},
	}
	for _, c := range cases {
		id, ver, _ := strings.Cut(c.distro, " ")
		d := doc(t, id, ver, "2026-10-25T00:00:00Z", nil, c.a)
		r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now})
		if len(r.PHP) != 1 {
			t.Errorf("%s: found %d PHP builds, want 1", c.name, len(r.PHP))
			continue
		}
		p := r.PHP[0]
		if p.Provider != c.provider || p.CVEs[cve19].Verdict != c.want {
			t.Errorf("%s: %s %s = %s (%s), want %s %s", c.name, p.Provider, cve19, p.CVEs[cve19].Verdict, p.CVEs[cve19].Why, c.provider, c.want)
		}
	}
}

// Freexian's rows apply only to Debian's own numbering: an unrecognized build with a
// higher epoch or another revision before the update counter isn't Freexian's.
func TestExtendedLTSOtherLines(t *testing.T) {
	for _, v := range []string{"1:7.3.31-1~deb10u1", "7.3.31-5~deb10u1", "7.3.31-1~deb11u20"} {
		d := doc(t, "debian", "10.13", "2026-10-25T00:00:00Z", nil, art{"php7.3-fpm", v, "deb", "", "", "/var/lib/dpkg/status"})
		r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now})
		if res := r.PHP[0].CVEs[cve19]; res.Verdict == FixedByVendorBackport || res.Verdict == FixedByDistroBackport {
			t.Errorf("%s: %s (%s)", v, res.Verdict, res.Why)
		}
	}
}

// A row for the build's distro release replaces the general ones, even when the general
// one is lower, the scoped one says "none", or the scoped one can't order the build.
func TestScopedRowWins(t *testing.T) {
	withBackports(t, `Remi,7.4,,7.4.33-1,CVE-2026-109618 CVE-2026-109619,https://example.org/any
Remi,7.4,rhel 9,7.4.33-40,CVE-2026-109618 CVE-2026-109619,https://example.org/rhel9
`)
	a := art{"php74-php-cli", "7.4.33-35.el9.remi", "rpm", "", "", "/var/lib/rpm/rpmdb.sqlite"}
	for release, want := range map[string]Verdict{"9.6": Vulnerable, "8.10": FixedByVendorBackport} {
		d := doc(t, "rhel", release, "2026-10-25T00:00:00Z", nil, a)
		if res := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now}).PHP[0].CVEs[cve19]; res.Verdict != want {
			t.Errorf("rhel %s: %s (%s), want %s", release, res.Verdict, res.Why, want)
		}
	}
}

// An ea-php build without cPanel's or CloudLinux's marker comes from a builder whichphp
// doesn't know. It must never reach the distro's security data, which doesn't cover it
// and would read the absence of a match as a backport.
func TestUnknownEaPHPBuilder(t *testing.T) {
	listed := map[string]grypejson.FeedStatus{cve18: {Listed: true}, cve19: {Listed: true}}
	for _, c := range []struct {
		distro, ver string
		a           art
	}{
		{"almalinux", "9.6", art{"ea-php74-php-fpm", "7.4.33-18.24.9", "rpm", "", "", "/var/lib/rpm/rpmdb.sqlite"}},
		{"ubuntu", "24.04", art{"ea-php81-php-cli", "8.1.34-4+11.9~hardened", "deb", "", "", "/var/lib/dpkg/status"}},
	} {
		d := doc(t, c.distro, c.ver, "2026-10-25T00:00:00Z", nil, c.a)
		r := Evaluate(Inputs{Doc: d, GrypeRan: true, Feed: listed, Now: now})
		p := r.PHP[0]
		if p.Source != SourceThirdParty || p.CVEs[cve19].Verdict != NeedsVendorConfirmation || r.Action != ActionUnknown {
			t.Errorf("%s %s: %s %s %s (%s), action %s", c.a.name, c.a.version, p.Source, p.Provider, p.CVEs[cve19].Verdict, p.CVEs[cve19].Why, r.Action)
		}
	}
}

// An image created before the fix can't hold a backport, so a build whichphp has no data
// for is vulnerable there, not a question for the vendor.
func TestNoBackportInAnImageOlderThanTheFix(t *testing.T) {
	d := doc(t, "centos", "7.9", "2026-09-01T00:00:00Z", nil, art{"php-fpm", "7.4.33-20.el7", "rpm", "", "", "/var/lib/rpm/Packages"})
	d.Artifacts[0].Metadata.Vendor = "GetPageSpeed LLC"
	res := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now}).PHP[0].CVEs[cve19]
	if res.Verdict != VulnerableEOL || !strings.Contains(res.Why, "predates the fix") {
		t.Fatalf("got %s (%s)", res.Verdict, res.Why)
	}
}

// TuxCare's rows name their distro, and within an EL8 module stream the version order,
// not the module build, decides.
func TestTuxCareLines(t *testing.T) {
	rpm := func(name, v string) art { return art{name, v, "rpm", "", "", "/var/lib/rpm/Packages"} }
	cases := []struct {
		name   string
		distro string
		a      art
		want   Verdict
	}{
		{"AlmaLinux 9.2 ESU build on Rocky", "rocky 9.2", rpm("php-cli", "8.0.30-1.el9_2.tuxcare.els20"), NeedsVendorConfirmation},
		{"earlier rebuild of the stream", "centos 8", rpm("php-fpm", "7.4.19-1.module_el8.5.0+2647+a4e241d9.tuxcare.els31"), Vulnerable},
		// Only the row's own distro build can show a build fixed: two lines could differ
		// in the module build alone.
		{"later rebuild of the stream", "centos 8", rpm("php-fpm", "7.4.19-1.module_el8.5.0+2750+0abc1234.tuxcare.els33"), NeedsVendorConfirmation},
		{"another module build, lower counter", "centos 8", rpm("php-fpm", "7.4.19-1.module_el8.5.0+2800+bbbbbbbb.tuxcare.els1"), Vulnerable},
		// A counter in another scheme can't be ordered against "elsN".
		{"another counter scheme", "centos 7", rpm("php-fpm", "5.4.16-48.el7.tuxcare.ol.els1"), NeedsVendorConfirmation},
		{"another counter name", "centos 7", rpm("php-fpm", "5.4.16-48.el7.tuxcare.esu1"), NeedsVendorConfirmation},
		{"counter with a leading zero", "centos 7", rpm("php-fpm", "5.4.16-48.el7.tuxcare.els021"), FixedByVendorBackport},
		{"counter with a suffix", "centos 7", rpm("php-fpm", "5.4.16-48.el7.tuxcare.els21.1"), NeedsVendorConfirmation},
		{"CentOS 8's build on AlmaLinux 8", "almalinux 8.10", rpm("php-fpm", "7.4.19-1.module_el8.5.0+2709+673b459a.tuxcare.els32"), NeedsVendorConfirmation},
	}
	for _, c := range cases {
		id, ver, _ := strings.Cut(c.distro, " ")
		d := doc(t, id, ver, "2026-10-25T00:00:00Z", nil, c.a)
		if res := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now}).PHP[0].CVEs[cve19]; res.Verdict != c.want {
			t.Errorf("%s: %s (%s), want %s", c.name, res.Verdict, res.Why, c.want)
		}
	}
}

// Every packager in packagers.csv must be one whichphp can recognize; a misspelled name
// would make its rows silently never apply.
func TestPackagersInTheTableAreRecognized(t *testing.T) {
	known := map[string]bool{"Freexian ELTS": true}
	for _, a := range []art{
		{"php8.1-cli", "8.1.34-9+deb.sury.org+1", "deb", "", "", ""},
		{"php-cli", "8.1.34-6.el9.remi", "rpm", "", "", ""},
		{"ea-php81-php-cli", "8.1.34-5.12.1.cpanel", "rpm", "", "", ""},
		{"ea-php81-php-cli", "1:8.1.34-4.el8.cloudlinux.1", "rpm", "", "", ""},
		{"php-cli", "1:8.1.32-1.module_el9.8.0+406+aadb97d2.cloudlinux.2", "rpm", "", "", ""},
		{"alt-php81-cli", "8.1.34-39.el8", "rpm", "", "", ""},
		{"alt-php81-cli", "8.1.34-39", "deb", "", "", ""},
		{"php-cli", "5.4.16-48.el7.tuxcare.els21", "rpm", "", "", ""},
	} {
		d := doc(t, "centos", "7", "", nil, a)
		known[thirdParty(d.Artifacts[0])] = true
	}
	for _, b := range advisory.Backports {
		if !known[b.Packager] {
			t.Errorf("packagers.csv names %q, which whichphp never recognizes", b.Packager)
		}
	}
}

func TestScopedRowsReplaceGeneralOnes(t *testing.T) {
	withBackports(t, `Remi,7.4,,7.4.33-31,CVE-2026-109618 CVE-2026-109619,https://example.org/any
Remi,7.4,centos 7,none,,https://example.org/el7
Remi,8.1,,1:8.1.34-6,CVE-2026-109618 CVE-2026-109619,https://example.org/any
Remi,8.1,rhel 9,8.1.34-40,CVE-2026-109618 CVE-2026-109619,https://example.org/rhel9
`)
	cases := []struct {
		name, distro, release string
		a                     art
		want                  Verdict
	}{
		{"scoped none row", "centos", "7.9", art{"php74-php-cli", "7.4.33-32.el7.remi", "rpm", "", "", ""}, VulnerableEOL},
		{"general row elsewhere", "rhel", "8.10", art{"php74-php-cli", "7.4.33-32.el8.remi", "rpm", "", "", ""}, FixedByVendorBackport},
		// The scoped row can't order a build with a higher epoch; the general row,
		// which could, describes other releases' builds.
		{"scoped row can't order it", "rhel", "9.6", art{"php81-php-cli", "1:8.1.34-35.el9.remi", "rpm", "", "", ""}, NeedsVendorConfirmation},
	}
	for _, c := range cases {
		d := doc(t, c.distro, c.release, "2026-10-25T00:00:00Z", nil, c.a)
		if res := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now}).PHP[0].CVEs[cve19]; res.Verdict != c.want {
			t.Errorf("%s: %s (%s), want %s", c.name, res.Verdict, res.Why, c.want)
		}
	}
}

// A placeholder creation date from a reproducible build says nothing about when the
// packages went in, so it can't rule a backport out, here or for an end-of-life distro.
func TestPlaceholderCreationDate(t *testing.T) {
	for _, created := range []string{"1970-01-01T00:00:00Z", "1980-01-01T00:00:01Z"} {
		d := doc(t, "centos", "7.9", created, nil, art{"php-fpm", "7.4.33-33.el7", "rpm", "", "", "/var/lib/rpm/Packages"})
		d.Artifacts[0].Metadata.Vendor = "GetPageSpeed LLC"
		r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now})
		if res := r.PHP[0].CVEs[cve19]; res.Verdict != NeedsVendorConfirmation || r.Image.BuiltBeforeFix != nil {
			t.Errorf("GetPageSpeed, created %s: %s (%s), builtBeforeFix %v", created, res.Verdict, res.Why, r.Image.BuiltBeforeFix)
		}
		d = doc(t, "ubuntu", "18.04", created, nil, art{"php7.2-fpm", "7.2.24-0ubuntu0.18.04.17+esm1", "deb", "", "", "/var/lib/dpkg/status"})
		if res := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now}).PHP[0].CVEs[cve19]; res.Verdict != Unknown {
			t.Errorf("Ubuntu 18.04 ESM, created %s: %s (%s), want UNKNOWN", created, res.Verdict, res.Why)
		}
	}
}

// Freexian's builds carry no marker; its rows rest on Debian's update counter, so every
// row must have one.
func TestExtendedLTSRowsHaveAnUpdateCounter(t *testing.T) {
	for _, b := range advisory.Backports {
		if distroExtenders[b.Packager] && (b.Distro == "" || !debianUpdateRE.MatchString(b.Fixed)) {
			t.Errorf("%s PHP %d.%d: %q needs a distro and a debNNu counter", b.Packager, b.Branch[0], b.Branch[1], b.Fixed)
		}
	}
}

// Every TuxCare row must be a build whose counter whichphp can read, or no build could
// ever be ordered against it.
func TestTuxCareRowsParse(t *testing.T) {
	for _, b := range advisory.Backports {
		if b.Packager != "TuxCare" {
			continue
		}
		if _, ok := parseTuxCare(b.Fixed); !ok {
			t.Errorf("TuxCare PHP %d.%d %s: can't read %q", b.Branch[0], b.Branch[1], b.Distro, b.Fixed)
		}
	}
}

// CentOS 7 has ended, so a package its security data doesn't cover, such as a
// GetPageSpeed build whose SBOM lacks the Vendor tag, is never taken for a backport.
func TestCentOS7IsEndOfLife(t *testing.T) {
	d := doc(t, "centos", "7.9", "2026-10-25T00:00:00Z", nil, art{"php-fpm", "7.4.33-33.el7", "rpm", "", "", "/var/lib/rpm/Packages"})
	listed := map[string]grypejson.FeedStatus{cve18: {Listed: true}, cve19: {Listed: true}}
	r := Evaluate(Inputs{Doc: d, GrypeRan: true, Feed: listed, Now: now})
	if res := r.PHP[0].CVEs[cve19]; res.Verdict == FixedByDistroBackport || r.Distro.Support != "end-of-life" {
		t.Fatalf("got %s (%s), support %s", res.Verdict, res.Why, r.Distro.Support)
	}
}

// When two rows share a module stream, the row for the build's own distro build decides.
func TestTuxCareExactRowFirst(t *testing.T) {
	withBackports(t, `TuxCare,7.4,centos 8,7.4.19-1.module_el8.5.0+2709+aaaaaaaa.tuxcare.els32,CVE-2026-109618 CVE-2026-109619,https://example.org/a
TuxCare,7.4,centos 8,7.4.19-1.module_el8.5.0+2600+bbbbbbbb.tuxcare.els20,CVE-2026-109618 CVE-2026-109619,https://example.org/b
`)
	for v, want := range map[string]Verdict{
		"7.4.19-1.module_el8.5.0+2709+aaaaaaaa.tuxcare.els33": FixedByVendorBackport,
		"7.4.19-1.module_el8.5.0+2709+aaaaaaaa.tuxcare.els25": Vulnerable,
	} {
		d := doc(t, "centos", "8", "2026-10-25T00:00:00Z", nil, art{"php-fpm", v, "rpm", "", "", "/var/lib/rpm/Packages"})
		if res := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now}).PHP[0].CVEs[cve19]; res.Verdict != want {
			t.Errorf("%s: %s (%s), want %s", v, res.Verdict, res.Why, want)
		}
	}
}
