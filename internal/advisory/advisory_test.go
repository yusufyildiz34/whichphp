package advisory

import "testing"

func TestSupport(t *testing.T) {
	cases := []struct {
		id, ver string
		want    DistroSupport
	}{
		{"debian", "13.7", Supported},
		{"debian", "12.11", Supported},
		{"debian", "10.1", EndOfLife},
		{"debian", "11.5", EndOfLife},
		{"ubuntu", "24.04", Supported},
		{"ubuntu", "20.04", EndOfLife},
		{"alpine", "3.24.2", Supported},
		{"alpine", "3.18.4", EndOfLife},
		{"rhel", "9.6", Supported},
		{"wolfi", "", Supported},
		{"gentoo", "2.17", SupportUnknown},
		{"debian", "", SupportUnknown},
	}
	for _, c := range cases {
		if got := Support(c.id, c.ver); got != c.want {
			t.Errorf("Support(%q, %q) = %v, want %v", c.id, c.ver, got, c.want)
		}
	}
}
