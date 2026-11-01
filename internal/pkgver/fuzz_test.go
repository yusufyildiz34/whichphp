package pkgver

import "testing"

// FuzzCompare feeds arbitrary version pairs, as they come from package databases in
// images, to both comparisons. They must never panic, every version must equal itself,
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
	} {
		f.Add(p[0], p[1])
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		for name, cmp := range map[string]func(string, string) int{"CompareRPM": CompareRPM, "CompareDeb": CompareDeb} {
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
