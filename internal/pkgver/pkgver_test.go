package pkgver

import "testing"

func TestCompareRPM(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// rpm's own rpmvercmp tests (tests/rpmvercmp.at).
		{"1.0", "1.0", 0},
		{"1.0", "2.0", -1},
		{"2.0.1", "2.0", 1},
		{"2.0.1a", "2.0.1", 1},
		{"5.5p1", "5.5p2", -1},
		{"5.5p10", "5.5p1", 1},
		{"10xyz", "10.1xyz", -1},
		{"xyz10", "xyz10.1", -1},
		{"xyz.4", "8", -1},
		{"8", "xyz.4", 1},
		{"1.0aa", "1.0a", 1},
		{"6.0.rc1", "6.0", 1},
		{"10b2", "10a1", 1},
		{"1b.fc17", "1.fc17", -1},
		{"1.0.", "1.0", 0},
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~rc1~git123", "1.0~rc1", -1},
		{"1.0", "1.0~", 1},
		{"1.0^", "1.0", 1},
		{"1.0^git1", "1.01", -1},
		{"1.0^20160101", "1.0.1", -1},
		{"1.0~rc1^git1", "1.0~rc1", 1},
		{"1.0^git1~pre", "1.0^git1", -1},
		{"0001", "1", 0},
		// Epoch and release.
		{"1:1.0-1", "2.0-1", 1},
		{"0:7.4.33-17.el8", "7.4.33-17.el8", 0},
		{"7.4.33-17.el8", "7.4.33-19.el8", -1},
		{"7.4.33-31.el9.remi", "7.4.33-30.el9.remi", 1},
		{"8.4.26-2.el9.cloudlinux.1", "8.4.26-2.el9.cloudlinux", 1},
		{"8.1.34-5.5.1.cpanel", "8.1.34-4.4.1.cpanel", 1},
		{"8.1.34", "8.1.34-5.el9", -1},
		{"8.1.34-", "8.1.34-5.el9", -1},
		{"99999999999999999999999:1", "2:1", 1},
	}
	for _, c := range cases {
		if got := CompareRPM(c.a, c.b); got != c.want {
			t.Errorf("CompareRPM(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareRPM(c.b, c.a); got != -c.want {
			t.Errorf("CompareRPM(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestCompareDeb(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// dpkg's own ordering rules (lib/dpkg/t/t-version.c, deb-version(7)).
		{"1.0", "1.0", 0},
		{"1.0-1", "1.0-2", -1},
		{"1:1.0", "2.0", 1},
		{"0:1.0", "1.0", 0},
		{"1.0~rc1", "1.0", -1},
		{"1.0~", "1.0", -1},
		{"1.0~~", "1.0~", -1},
		{"1.0a", "1.0", 1},
		{"1.0a", "1.0+", -1},
		{"1.0+deb", "1.0", 1},
		{"1.0", "1.00", 0},
		{"1.2.3", "1.2.10", -1},
		// Real-world forms.
		{"7.3.31-1~deb10u12", "7.3.31-1~deb10u2", 1},
		{"1:7.4.33-31+0~20261022.110+debian12~1.gbp2e8c1b", "7.4.33-31", 1},
		{"1:7.4.33-31+0~20261022.110+debian12~1.gbp2e8c1b", "1:7.4.33-31", 1},
		{"1:7.4.33-30+0~20260901.100+debian12~1.gbp2e8c1b", "1:7.4.33-31", -1},
		{"8.3.6-0ubuntu0.24.04.13", "8.3.6-0ubuntu0.24.04.9", 1},
		{"7.2.24-0ubuntu0.18.04.17+esm14", "7.2.24-0ubuntu0.18.04.17", 1},
		{"8.3.36-1+ubuntu24.04.1+deb.sury.org+1", "8.3.36-1", 1},
		{"99999999999999999999999:1", "2:1", 1},
	}
	for _, c := range cases {
		if got := CompareDeb(c.a, c.b); got != c.want {
			t.Errorf("CompareDeb(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareDeb(c.b, c.a); got != -c.want {
			t.Errorf("CompareDeb(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}
