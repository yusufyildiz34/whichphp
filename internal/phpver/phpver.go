// Package phpver parses PHP version strings as they appear in binaries,
// package databases and image metadata.
package phpver

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Version is an upstream PHP version, with an optional pre-release marker.
type Version struct {
	Major, Minor, Patch int
	// Pre is "", "dev", "alpha", "beta" or "rc".
	Pre    string
	PreNum int
	// Raw is the string the version was parsed from.
	Raw string
}

// The pre-release marker must follow the patch number directly (optionally after one
// separator). Distro suffixes such as "-1.devuan1" or "-0ubuntu0.24.04.13" therefore
// don't count as pre-releases.
var versionRE = regexp.MustCompile(`(?i)^(\d+)\.(\d+)\.(\d+)(?:[-_.~]?(rc|alpha|beta|dev)(\d*))?(?:$|[^a-z])`)

var epochRE = regexp.MustCompile(`^\d+:`)

// Parse extracts the upstream PHP version from a package or binary version string, for
// example "8.3.6-0ubuntu0.24.04.13", "1:8.4.27-1", "8.2.29-2" (Bitnami), "8.4.26-dev",
// "8.2.30RC1" or "8.3.35-1+deb.sury.org+1". It returns false when the string doesn't
// start with a version, such as "The PHP Group" or "2:93ubuntu2".
func Parse(s string) (Version, bool) {
	raw := s
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "v"), "V")
	s = epochRE.ReplaceAllString(s, "")
	m := versionRE.FindStringSubmatch(s)
	if m == nil {
		return Version{}, false
	}
	v := Version{Raw: raw}
	v.Major, _ = strconv.Atoi(m[1])
	v.Minor, _ = strconv.Atoi(m[2])
	v.Patch, _ = strconv.Atoi(m[3])
	if m[4] != "" {
		v.Pre = strings.ToLower(m[4])
		if m[5] != "" {
			v.PreNum, _ = strconv.Atoi(m[5])
		}
	}
	return v, true
}

// Triple returns the numeric part of the version.
func (v Version) Triple() [3]int { return [3]int{v.Major, v.Minor, v.Patch} }

// Branch returns the major and minor version, for example [8 3].
func (v Version) Branch() [2]int { return [2]int{v.Major, v.Minor} }

// IsPre reports whether the version is a development or pre-release build.
func (v Version) IsPre() bool { return v.Pre != "" }

// String renders the parsed version, for example "8.4.27" or "8.6.0rc4".
func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += v.Pre
		if v.PreNum > 0 {
			s += strconv.Itoa(v.PreNum)
		}
	}
	return s
}

// Less compares numeric triples.
func Less(a, b [3]int) bool {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// FormatTriple renders a numeric triple as "8.4.27".
func FormatTriple(t [3]int) string { return fmt.Sprintf("%d.%d.%d", t[0], t[1], t[2]) }
