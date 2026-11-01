package advisory

import (
	"bytes"
	_ "embed"
	"encoding/csv"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/yusufyildiz34/whichphp/internal/phpver"
)

// Packagers that backport the fixes into an older upstream version keep the old version
// number, so only their own package releases tell a fixed build from an unfixed one.
// packagers.csv lists, per packager and PHP branch, the first package release with the
// fixes, or "none" where the packager said it published no fix. Every row has a source:
// the packager's own advisory, changelog, tracker or repository, never a blog or forum.
//
//go:embed packagers.csv
var packagersCSV []byte

// Backport is one row of packagers.csv.
type Backport struct {
	Packager string
	// Branch is the PHP branch the packager's build ships, for example [7 4].
	Branch [2]int
	// Distro limits the row to one distro release ("debian 10"); empty means any.
	Distro string
	// Fixed is the first fixed package version, compared the way the package's own
	// format orders versions. "{el}" in it stands for the installed build's EL dist tag
	// ("el8"). Empty means the packager published no fix.
	Fixed string
	CVEs  []string
	// Source links to the packager's own statement.
	Source string
}

// Fixes reports whether the row's build fixes cve.
func (b Backport) Fixes(cve string) bool { return slices.Contains(b.CVEs, cve) }

// Backports are the rows of packagers.csv.
var Backports = mustParseBackports(packagersCSV)

// BackportsFor returns the rows for a packager's build of a PHP branch on a distro
// release, given as "<id> <version>" as NormalizeRelease reduces it.
func BackportsFor(packager string, branch [2]int, distro string) []Backport {
	var out []Backport
	for _, b := range Backports {
		if b.Packager == packager && b.Branch == branch && (b.Distro == "" || b.Distro == distro) {
			out = append(out, b)
		}
	}
	return out
}

func mustParseBackports(data []byte) []Backport {
	bs, err := ParseBackports(data)
	if err != nil {
		panic("advisory: packagers.csv: " + err.Error())
	}
	return bs
}

// fixedRE is the shape of a first fixed release: an optional numeric epoch, a version
// that starts with a digit, and a release. Anything looser can order every build above
// it: "(none):7.4.33-81" (rpm's way of printing no epoch) sorts below 7.4.33-1.
var fixedRE = regexp.MustCompile(`^(\d+:)?\d[^:\s{}]*-[0-9A-Za-z][^-:\s{}]*$`)

// ParseBackports reads packagers.csv. It rejects rows without a source, with an unknown
// CVE or with a branch that isn't "major.minor", so a bad edit fails the tests.
func ParseBackports(data []byte) ([]Backport, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.Comment = '#'
	r.FieldsPerRecord = 6
	header, err := r.Read()
	if err != nil {
		return nil, err
	}
	want := []string{"packager", "branch", "distro", "fixed", "cves", "source"}
	if strings.Join(header, ",") != strings.Join(want, ",") {
		return nil, fmt.Errorf("header is %q, want %q", header, want)
	}
	known := map[string]bool{}
	for _, c := range CVEs {
		known[c] = true
	}
	var out []Backport
	for {
		rec, err := r.Read()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		line, _ := r.FieldPos(0)
		b := Backport{Packager: rec[0], Distro: rec[2], Fixed: rec[3], Source: rec[5]}
		if b.Packager == "" {
			return nil, fmt.Errorf("line %d: no packager", line)
		}
		major, minor, ok := strings.Cut(rec[1], ".")
		var e1, e2 error
		b.Branch[0], e1 = strconv.Atoi(major)
		b.Branch[1], e2 = strconv.Atoi(minor)
		if !ok || e1 != nil || e2 != nil {
			return nil, fmt.Errorf("line %d: branch %q isn't major.minor", line, rec[1])
		}
		switch {
		case b.Fixed == "none":
			b.Fixed = ""
		case b.Fixed == "":
			return nil, fmt.Errorf("line %d: no fixed version (write \"none\" if the packager published no fix)", line)
		}
		for _, c := range strings.Fields(rec[4]) {
			if !known[c] {
				return nil, fmt.Errorf("line %d: unknown CVE %q", line, c)
			}
			b.CVEs = append(b.CVEs, c)
		}
		if b.Fixed != "" && len(b.CVEs) == 0 {
			return nil, fmt.Errorf("line %d: a fixed build must name the CVEs it fixes", line)
		}
		if b.Fixed != "" && !fixedRE.MatchString(strings.ReplaceAll(b.Fixed, "{el}", "el0")) {
			return nil, fmt.Errorf("line %d: %q isn't [epoch:]version-release with a numeric epoch and {el} as the only placeholder", line, b.Fixed)
		}
		if v, ok := phpver.Parse(b.Fixed); b.Fixed != "" && (!ok || v.Branch() != b.Branch) {
			return nil, fmt.Errorf("line %d: %q isn't a PHP %d.%d version", line, b.Fixed, b.Branch[0], b.Branch[1])
		}
		if b.Fixed == "" && len(b.CVEs) > 0 {
			return nil, fmt.Errorf("line %d: a row without a fix applies to every CVE; leave the CVEs empty", line)
		}
		if u, err := url.Parse(b.Source); err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("line %d: source %q isn't an https URL", line, b.Source)
		}
		out = append(out, b)
	}
}
