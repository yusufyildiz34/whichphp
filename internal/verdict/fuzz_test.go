package verdict

import (
	"strings"
	"testing"
)

// FuzzPackagerVerdict feeds arbitrary package names, versions, distros and creation
// dates, as they come from an SBOM, through packager recognition and the packagers.csv
// comparisons. Nothing may panic, and a vendor backport verdict must always cite the row
// it rests on.
func FuzzPackagerVerdict(f *testing.F) {
	for _, s := range [][7]string{
		{"php8.0-fpm", "1:8.0.30-25+0~20261021.88+debian12~1.gbpabebea", "deb", "debian", "12.12", "", "2026-10-25T00:00:00Z"},
		{"ea-php82-php-fpm", "1:8.2.34-2.el9.cloudlinux.1", "rpm", "cloudlinux", "9.6", "", "1970-01-01T00:00:00Z"},
		{"php-fpm", "7.4.19-1.module_el8.5.0+2709+673b459a.tuxcare.els32", "rpm", "centos", "8", "", "2026-10-25T00:00:00Z"},
		{"php7.3-cli", "7.3.31-1~deb10u16", "deb", "debian", "10.13", "", "2021-03-01T00:00:00Z"},
		{"php-fpm", "7.4.33-33.el7", "rpm", "centos", "7.9", "GetPageSpeed LLC", "2026-09-01T00:00:00Z"},
		{"alt-php73-cli", "1:7.3.33-82.el9", "rpm", "cloudlinux", "9.6", "", "2026-10-25T00:00:00Z"},
		{"php82-fpm", "8.2.16.tuxcare.els10-r0", "apk", "alpine", "3.18", "", ""},
		{"alt-php74-fpm", "7.4.33-r13", "apk", "alpine", "3.23.1", "", "2026-10-25T00:00:00Z"},
		{"alt-php74-cli", "7.4.33-81", "apk", "alpine", "3.22", "", ""},
		{"php-fpm", "1:7.2.24-1.module_el8.4.0+6493+7c76a223.cloudlinux.1", "rpm", "cloudlinux", "8.10", "", "2026-10-25T00:00:00Z"},
		{"php-cli", "1:8.0.30-1.module_el8.8.0+6722+42d2b711.cloudlinux", "rpm", "cloudlinux", "8", "", ""},
		{"ea-php81-php-cli", "1:", "deb", "", "", "", "not a date"},
	} {
		f.Add(s[0], s[1], s[2], s[3], s[4], s[5], s[6])
	}
	f.Fuzz(func(t *testing.T, name, version, typ, distro, release, vendor, created string) {
		d := doc(t, distro, release, created, nil, art{name, version, typ, "", "", "/var/lib/dpkg/status"})
		for i := range d.Artifacts {
			d.Artifacts[i].Metadata.Vendor = vendor
		}
		r := Evaluate(Inputs{Doc: d, GrypeRan: true, Now: now})
		for _, p := range r.PHP {
			for cve, res := range p.CVEs {
				if res.Verdict == FixedByVendorBackport && !strings.Contains(res.Why, "https://") {
					t.Fatalf("%s %s %s on %s %s: %s without a source: %s", typ, name, version, distro, release, cve, res.Why)
				}
			}
		}
	})
}
