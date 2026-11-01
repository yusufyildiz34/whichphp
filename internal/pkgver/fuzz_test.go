package pkgver

import "testing"

// FuzzCompare feeds arbitrary version pairs, as they come from package databases in
// images, to every comparison. They must never panic, every version must equal itself,
// and swapping the arguments must flip the result.
func FuzzCompare(f *testing.F) {
	for _, p := range [][2]string{
		{"7.4.33-17.el8", "7.4.33-19.el8"},
		{"1:7.4.33-31+0~20261022.110+debian12~1.gbp2e8c1b", "7.4.33-31"},
		{"1.0~rc1^git1", "1.0^"},
		{"", "~"},
		{"1:", ":1"},
		{"-", "--"},
		{"99999999999999999999999:1", "0:1"},
		{"8.2.16-r0", "8.2.16.tuxcare.els10-r0"},
		{"0.1.0_alpha_pre2~1234abcd-r1", "0.1_p1"},
		{"7.4.33-r13", "7.4.33-81"},
	} {
		f.Add(p[0], p[1])
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		ValidAPK(a)
		for name, cmp := range map[string]func(string, string) int{"CompareRPM": CompareRPM, "CompareDeb": CompareDeb, "CompareAPK": CompareAPK} {
			if got := cmp(a, a); got != 0 {
				t.Fatalf("%s(%q, %q) = %d, want 0", name, a, a, got)
			}
			ab, ba := cmp(a, b), cmp(b, a)
			if ab < -1 || ab > 1 || ab != -ba {
				t.Fatalf("%s(%q, %q) = %d but %s(%q, %q) = %d", name, a, b, ab, name, b, a, ba)
			}
		}
	})
}
