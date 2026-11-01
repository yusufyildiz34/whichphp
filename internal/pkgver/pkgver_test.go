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

func TestCompareAPK(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// apk-tools' own tests (test/unit/version.data).
		{"2.34", "0.1.0_alpha", 1},
		{"23_foo", "4_beta", 1},
		{"1.0", "1.0bc", -1},
		{"0.1.0_alpha", "0.1.0_alpha", 0},
		{"0.1.0_alpha2", "0.1.0_alpha", 1},
		{"1.1", "1.1_alpha1", 1},
		{"1.0.4-r3", "1.0.4-r4", -1},
		{"1.2.1", "1.2", 1},
		{"0.12", "0.13_beta1", -1},
		{"1.2.12.1", "1.2.13", -1},
		{"3.1_p16", "3.1_p17", -1},
		{"1.06-r6", "006", -1},
		{"1.2.2-r1", "1.2.2", 1},
		{"2.3.0b-r1", "2.3.0b-r2", -1},
		{"2.5.1-r8", "2.5.1a-r1", -1},
		{"0.10.0", "0.10.1_rc1", -1},
		{"2.0.0_rc3-r1", "1.5", 1},
		{"4.5_p1-r1", "4.5_p1", 1},
		{"1.8.5", "1.8.5_p2", -1},
		{"1.3.5-r10", "1.3.5-r9", 1},
		{"2.9.11_pre20051101-r3", "2.9.11_pre20051101", 1},
		{"0.1.0_alpha_pre2", "0.1.0_alpha", -1},
		{"1.0_p10-r0", "1.0_p9-r0", 1},
		{"8.2.0", "8.2.001", -1},
		{"8.2.0015", "8.2.002", -1},
		{"1.0~1234-r1", "1.0~2345-r0", -1},
		{"1.0~1234-r1", "1.0~1234-r0", 1},
		// Real-world forms: Alpine's own PHP and TuxCare's alt-php for Alpine.
		{"8.3.24-r1", "8.3.24-r0", 1},
		{"8.4.27-r0", "8.4.26-r2", 1},
		{"8.6.0_rc4-r0", "8.6.0-r0", -1},
		{"7.4.33-r13", "7.4.33-r12", 1},
		{"7.4.33-r13", "7.4.33-r9", 1},
		// Versions apk-tools can't read compare equal from the first bad character on.
		{"7.4.33-81", "7.4.33-1", 0},
		{"99999999999999999999999-r1", "2-r1", 1},
	}
	for _, c := range cases {
		if got := CompareAPK(c.a, c.b); got != c.want {
			t.Errorf("CompareAPK(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareAPK(c.b, c.a); got != -c.want {
			t.Errorf("CompareAPK(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestValidAPK(t *testing.T) {
	// apk-tools' own tests (test/unit/version.data), and the forms whichphp meets.
	for _, v := range []string{"1.2", "0.1_pre2", "0.1_pre2~1234abcd", "0.1_p1_pre2", "0.1_git20240101_pre1", "8.2.16-r0", "7.4.33-r13"} {
		if !ValidAPK(v) {
			t.Errorf("ValidAPK(%q) = false", v)
		}
	}
	for _, v := range []string{
		"", "0.1bc", "0.1a1", "0.1a.1", "0.1_pre2~", "0.1_pre2~1234xbcd", "0.1_foobar", "0.1-pre1.1",
		"0.1-r", "0.1-r2_pre1", "0.1-r2-r3", "0.1-r2.1", ".1", "a", "-r1", "0.1_", "0.1__alpha",
		// A deb release and TuxCare's marker aren't apk syntax.
		"7.4.33-81", "8.2.16.tuxcare.els10-r0",
	} {
		if ValidAPK(v) {
			t.Errorf("ValidAPK(%q) = true", v)
		}
	}
}
