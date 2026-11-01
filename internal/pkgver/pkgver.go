// Package pkgver compares package versions the way rpm and dpkg do. Packagers that
// backport fixes keep the upstream PHP version and change only the package release, so
// whether a build is fixed depends on this order, not on the PHP version.
package pkgver

import "strings"

// CompareRPM compares two rpm versions of the form [epoch:]version[-release], as Syft
// reports them, and returns -1, 0 or 1. A missing epoch is 0. A missing release sorts
// below any release: unlike a dependency, an installed build without one can't be
// shown to be at or above a fixed build.
func CompareRPM(a, b string) int {
	ea, va, ra := splitRPM(a)
	eb, vb, rb := splitRPM(b)
	if c := compareNumeric(ea, eb); c != 0 {
		return c
	}
	if c := rpmvercmp(va, vb); c != 0 {
		return c
	}
	return rpmvercmp(ra, rb)
}

func splitRPM(s string) (epoch, version, release string) {
	if i := strings.IndexByte(s, ':'); i >= 0 && allDigits(s[:i]) {
		epoch, s = s[:i], s[i+1:]
	}
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		return epoch, s[:i], s[i+1:]
	}
	return epoch, s, ""
}

// rpmvercmp is rpm's segment comparison (rpmio/rpmvercmp.c): alphanumeric segments are
// compared in turn, numbers numerically and letters as strings, a number beats letters,
// "~" sorts before everything (even the end) and "^" after the end but before anything
// else.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		ca, cb := at(a, i), at(b, j)
		if ca == '~' || cb == '~' {
			if ca != '~' {
				return 1
			}
			if cb != '~' {
				return -1
			}
			i, j = i+1, j+1
			continue
		}
		if ca == '^' || cb == '^' {
			switch {
			case i == len(a):
				return -1
			case j == len(b):
				return 1
			case ca != '^':
				return 1
			case cb != '^':
				return -1
			}
			i, j = i+1, j+1
			continue
		}
		if i == len(a) || j == len(b) {
			break
		}
		class := isAlpha
		if isDigit(a[i]) {
			class = isDigit
		}
		ei, ej := i, j
		for ei < len(a) && class(a[ei]) {
			ei++
		}
		for ej < len(b) && class(b[ej]) {
			ej++
		}
		if ej == j {
			// b has a segment of the other kind here; a number beats letters.
			if isDigit(a[i]) {
				return 1
			}
			return -1
		}
		var c int
		if isDigit(a[i]) {
			c = compareNumeric(a[i:ei], b[j:ej])
		} else {
			c = strings.Compare(a[i:ei], b[j:ej])
		}
		if c != 0 {
			return c
		}
		i, j = ei, ej
	}
	switch {
	case i == len(a) && j == len(b):
		return 0
	case i == len(a):
		return -1
	}
	return 1
}

// CompareDeb compares two Debian versions of the form [epoch:]upstream[-revision], as
// dpkg does, and returns -1, 0 or 1.
func CompareDeb(a, b string) int {
	ea, ua, ra := splitDeb(a)
	eb, ub, rb := splitDeb(b)
	if c := compareNumeric(ea, eb); c != 0 {
		return c
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

func splitDeb(s string) (epoch, upstream, revision string) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ':'); i >= 0 && allDigits(s[:i]) {
		epoch, s = s[:i], s[i+1:]
	}
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		return epoch, s[:i], s[i+1:]
	}
	return epoch, s, ""
}

// verrevcmp is dpkg's comparison (lib/dpkg/version.c): runs of non-digits are compared
// character by character, with "~" before the end, the end before letters and letters
// before other characters; runs of digits are compared numerically.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			oa, ob := order(at(a, i)), order(at(b, j))
			if oa != ob {
				return sign(oa - ob)
			}
			i, j = i+1, j+1
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		firstDiff := 0
		for i < len(a) && j < len(b) && isDigit(a[i]) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i, j = i+1, j+1
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

func order(c byte) int {
	switch {
	case isDigit(c), c == 0:
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

// CompareEpoch compares the epochs of two rpm or Debian versions; a version without one
// has epoch 0.
func CompareEpoch(a, b string) int {
	ea, _, _ := splitDeb(a)
	eb, _, _ := splitDeb(b)
	return compareNumeric(ea, eb)
}

// compareNumeric compares two strings of digits by value, without converting them, so
// that any length works. An empty string is 0.
func compareNumeric(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return sign(len(a) - len(b))
	}
	return strings.Compare(a, b)
}

// at returns the byte at i, or 0 past the end, as C's terminating NUL.
func at(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }
func isAlpha(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }
func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return s != ""
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
