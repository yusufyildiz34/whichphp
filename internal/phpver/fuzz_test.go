package phpver

import "testing"

// FuzzParse feeds arbitrary version strings, as they come from image metadata, to
// Parse. It must never panic; a version it accepts must render to a string that parses
// back to the same version, and must not sort before or after itself.
func FuzzParse(f *testing.F) {
	for _, s := range []string{"8.4.26", "8.3.6-0ubuntu0.24.04.13", "1:7.4.33-1+deb11u5", "8.6.0RC4", "8.5.0-dev", "7.3.27-1~deb10u1", "", "8", "9999999999999999999.1.1", "8.4.99999999999999999999", "8.6.0rc0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, ok := Parse(s)
		if !ok {
			return
		}
		for _, n := range v.Triple() {
			if n < 0 {
				t.Fatalf("Parse(%q) gave a negative component: %+v", s, v)
			}
		}
		if Less(v.Triple(), v.Triple()) {
			t.Fatalf("Parse(%q): %v sorts before itself", s, v)
		}
		w, ok := Parse(v.String())
		if !ok || w.Triple() != v.Triple() || w.Pre != v.Pre || w.PreNum != v.PreNum {
			t.Fatalf("Parse(%q) = %+v, but its string %q parses to %+v (ok=%v)", s, v, v.String(), w, ok)
		}
	})
}
