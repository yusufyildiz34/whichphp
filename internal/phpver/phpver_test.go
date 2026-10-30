package phpver

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in     string
		ok     bool
		triple [3]int
		pre    string
		preNum int
	}{
		{"8.4.27", true, [3]int{8, 4, 27}, "", 0},
		{"8.3.6-0ubuntu0.24.04.13", true, [3]int{8, 3, 6}, "", 0},
		{"1:8.4.27-1", true, [3]int{8, 4, 27}, "", 0},
		{"8.2.29-2", true, [3]int{8, 2, 29}, "", 0},
		{"8.3.35-1+deb.sury.org+1", true, [3]int{8, 3, 35}, "", 0},
		{"7.3.27-1~deb10u1", true, [3]int{7, 3, 27}, "", 0},
		{"8.4.26-dev", true, [3]int{8, 4, 26}, "dev", 0},
		{"8.2.30RC1", true, [3]int{8, 2, 30}, "rc", 1},
		{"8.6.0RC4", true, [3]int{8, 6, 0}, "rc", 4},
		{"8.6.0-rc3", true, [3]int{8, 6, 0}, "rc", 3},
		{"8.4.27-1.devuan1", true, [3]int{8, 4, 27}, "", 0},
		{"8.4.26]", true, [3]int{8, 4, 26}, "", 0},
		{"The PHP Group", false, [3]int{}, "", 0},
		{"2:93ubuntu2", false, [3]int{}, "", 0},
		{"", false, [3]int{}, "", 0},
	}
	for _, c := range cases {
		v, ok := Parse(c.in)
		if ok != c.ok {
			t.Errorf("Parse(%q) ok = %v, want %v", c.in, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if v.Triple() != c.triple || v.Pre != c.pre || v.PreNum != c.preNum {
			t.Errorf("Parse(%q) = %v %q %d, want %v %q %d", c.in, v.Triple(), v.Pre, v.PreNum, c.triple, c.pre, c.preNum)
		}
	}
}

func TestLess(t *testing.T) {
	if !Less([3]int{8, 4, 26}, [3]int{8, 4, 27}) || Less([3]int{8, 4, 27}, [3]int{8, 4, 27}) || Less([3]int{8, 5, 0}, [3]int{8, 4, 99}) {
		t.Fatal("Less is wrong")
	}
}
