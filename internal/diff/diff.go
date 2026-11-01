// Package diff compares two whichphp image reports, from before and after a change such
// as a rebuild, and says what changed in PHP and whether the change fixed it.
package diff

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/yusufyildiz34/whichphp/internal/advisory"
	"github.com/yusufyildiz34/whichphp/internal/phpini"
	"github.com/yusufyildiz34/whichphp/internal/phpver"
	"github.com/yusufyildiz34/whichphp/internal/report"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

// Outcome sums up a comparison; Diff.Summary says it in words.
type Outcome string

const (
	// Fixed: the after image is OK, every fix in it is proven, and the before image
	// wasn't OK.
	Fixed Outcome = "FIXED"
	// Improved: the before image needed action, and the after image is unknown. Or the
	// after image is OK, and the before image wasn't, but a fix in it is a distro
	// backport whose feed coverage wasn't confirmed.
	Improved Outcome = "IMPROVED"
	// NoPHPAfter: the before image had PHP, and none was found in the after image,
	// which proves nothing: a PHP build whichphp doesn't recognize would be missed.
	NoPHPAfter Outcome = "NO_PHP_AFTER"
	// StillVulnerable, StillUnknown and StillOK: PHP changed, but the action didn't.
	StillVulnerable Outcome = "STILL_VULNERABLE"
	StillUnknown    Outcome = "STILL_UNKNOWN"
	StillOK         Outcome = "STILL_OK"
	// GotWorse: the after image asks for more than the before image did. Or it asks for
	// the same, but a CVE verdict got worse or session.upload_progress.enabled was
	// turned back on, and nothing got better.
	GotWorse Outcome = "GOT_WORSE"
	// NoPHPChange: the same PHP builds, verdicts, setting and action in both images.
	NoPHPChange Outcome = "NO_PHP_CHANGE"
)

var summaries = map[Outcome]string{
	Fixed:           "Fixed by this change",
	Improved:        "Better, but not proven fixed",
	NoPHPAfter:      "No PHP found in the after image, which isn't proof of a fix",
	StillVulnerable: "Still vulnerable",
	StillUnknown:    "Still unknown",
	StillOK:         "Still OK",
	GotWorse:        "Got worse",
	NoPHPChange:     "No PHP change",
}

// What happened to a PHP build.
const (
	Added     = "added"
	Removed   = "removed"
	Changed   = "changed" // another version, or another name for the same SAPI
	Unchanged = "unchanged"
)

// How a build in both images was paired with its counterpart, in the order they are
// tried.
const (
	MatchName   = "name"   // the same name and SAPI
	MatchFamily = "family" // the same name apart from the PHP version in it, and the same SAPI
	MatchSAPI   = "sapi"   // the only build of its SAPI left in each image
)

// Change is a value before and after the change; a side without the value leaves it
// empty.
type Change struct {
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

// VerdictChange is a verdict before and after the change. Unconfirmed marks each side
// whose FIXED_BY_DISTRO_BACKPORT rests only on the absence of a Grype match, without
// confirming that the distro's security data covers the CVE.
type VerdictChange struct {
	Before      string `json:"before,omitempty"`
	After       string `json:"after,omitempty"`
	Unconfirmed *Sides `json:"unconfirmed,omitempty"`
}

// Sides says which of the two images something applies to.
type Sides struct {
	Before bool `json:"before,omitempty"`
	After  bool `json:"after,omitempty"`
}

// Image identifies one of the two images.
type Image struct {
	// Name is the image's tag, the reference it was given as, or an archive's base name.
	Name         string `json:"name"`
	Digest       string `json:"digest,omitempty"`
	ImageID      string `json:"imageID,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	Created      string `json:"created,omitempty"`
	Distro       string `json:"distro,omitempty"`
	// Whichphp is the version of whichphp that made the image's report.
	Whichphp string `json:"whichphpVersion,omitempty"`
	// Notes are the notes in the image's own report.
	Notes []string `json:"notes,omitempty"`
}

// PHP summarizes one PHP build.
type PHP struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Source   string `json:"source"`
	Provider string `json:"provider,omitempty"`
	SAPI     string `json:"sapi"`
}

// Build is one PHP build in either image, with its counterpart in the other.
type Build struct {
	// Change is added, removed, changed or unchanged.
	Change string `json:"change"`
	// Match says how a build in both images was paired: name, family or sapi.
	Match  string `json:"match,omitempty"`
	Before *PHP   `json:"before,omitempty"`
	After  *PHP   `json:"after,omitempty"`
	// CVEs is the build's verdict per CVE in each image.
	CVEs map[string]VerdictChange `json:"cves"`

	before, after int // positions in the reports, for a stable order
}

// Diff is the comparison of two reports.
type Diff struct {
	Tool    string  `json:"tool"`
	Version string  `json:"version"`
	Outcome Outcome `json:"outcome"`
	Summary string  `json:"summary"`
	Before  Image   `json:"before"`
	After   Image   `json:"after"`
	// Action is each image's overall action; the after image's sets the exit code.
	Action Change `json:"action"`
	// Verdicts is each image's verdict per CVE, the worst across its PHP builds.
	Verdicts map[string]VerdictChange `json:"verdicts"`
	// UploadProgress is the effective image default of session.upload_progress.enabled.
	UploadProgress Change `json:"uploadProgress"`
	// PHP lists changed builds first, then added, removed and unchanged ones.
	PHP   []Build  `json:"php"`
	Notes []string `json:"notes,omitempty"`
}

// Options control a comparison.
type Options struct {
	// FailOnMitigation counts session.upload_progress on as action needed in both
	// images, as "whichphp image --fail-on-mitigation" does.
	FailOnMitigation bool
	// Version is the running whichphp's version. A report made by another version
	// gets a note, since its verdicts follow that version's rules.
	Version string
}

// Compare compares the report of an image before a change with the report after it.
func Compare(before, after verdict.Report, opt Options) Diff {
	if opt.FailOnMitigation {
		before.Action, after.Action = withMitigation(before), withMitigation(after)
	}
	d := Diff{
		Tool:           "whichphp",
		Version:        opt.Version,
		Before:         describe(before),
		After:          describe(after),
		Action:         Change{Before: string(before.Action), After: string(after.Action)},
		Verdicts:       map[string]VerdictChange{},
		UploadProgress: Change{Before: uploadProgress(before), After: uploadProgress(after)},
		Notes:          notes(before, after, opt.Version),
	}
	limit := func(side string, php []verdict.PHP) []verdict.PHP {
		if len(php) <= maxBuilds {
			return php
		}
		d.Notes = append(d.Notes, fmt.Sprintf("The %s image lists %d PHP builds; only the first %d are compared one by one.", side, len(php), maxBuilds))
		return php[:maxBuilds]
	}
	d.PHP = match(limit("before", before.PHP), limit("after", after.PHP))
	for cve, v := range before.Verdicts {
		c := d.Verdicts[cve]
		c.Before = string(v)
		if v == verdict.FixedByDistroBackport && unconfirmed(before.PHP, cve) {
			c.Unconfirmed = &Sides{Before: true}
		}
		d.Verdicts[cve] = c
	}
	for cve, v := range after.Verdicts {
		c := d.Verdicts[cve]
		c.After = string(v)
		if v == verdict.FixedByDistroBackport && unconfirmed(after.PHP, cve) {
			c.Unconfirmed = withAfter(c.Unconfirmed)
		}
		d.Verdicts[cve] = c
	}
	d.Outcome = outcome(d)
	d.Summary = summaries[d.Outcome]
	return d
}

// ExitCode is the after image's exit code, as "whichphp image" gives it: 0 for OK or no
// PHP, 1 for action needed, 2 for unknown.
func (d Diff) ExitCode() int {
	switch verdict.Action(d.Action.After) {
	case verdict.ActionOK, verdict.ActionNoPHP:
		return 0
	case verdict.ActionNeeded:
		return 1
	}
	return 2
}

// withMitigation is a report's action when session.upload_progress on counts as action
// needed. Reports from "whichphp image --fail-on-mitigation" already have it.
func withMitigation(r verdict.Report) verdict.Action {
	if len(r.PHP) > 0 && uploadProgress(r) == "on" {
		return verdict.ActionNeeded
	}
	return r.Action
}

func uploadProgress(r verdict.Report) string {
	return r.Settings[phpini.UploadProgress].Effective
}

// unconfirmed reports whether a build's FIXED_BY_DISTRO_BACKPORT for the CVE rests
// only on the absence of a Grype match.
func unconfirmed(php []verdict.PHP, cve string) bool {
	for _, p := range php {
		if r := p.CVEs[cve]; r.Verdict == verdict.FixedByDistroBackport && r.Unconfirmed {
			return true
		}
	}
	return false
}

// withAfter marks the after side, keeping the before side's mark.
func withAfter(s *Sides) *Sides {
	if s == nil {
		return &Sides{After: true}
	}
	return &Sides{Before: s.Before, After: true}
}

func describe(r verdict.Report) Image {
	return Image{
		Name:         report.ImageLabel(r),
		Digest:       r.Image.ManifestDigest,
		ImageID:      r.Image.ImageID,
		Architecture: r.Image.Architecture,
		Created:      r.Image.Created,
		Distro:       strings.TrimSpace(r.Distro.ID + " " + r.Distro.Version),
		Whichphp:     r.Version,
		Notes:        r.Notes,
	}
}

// notes warns about comparisons whose differences may not come from the change, and
// about reports whose verdicts follow the rules of another version of whichphp than
// the one running.
func notes(before, after verdict.Report, running string) []string {
	var out []string
	b, a := before.Image, after.Image
	if b.Architecture != "" && a.Architecture != "" && b.Architecture != a.Architecture {
		out = append(out, fmt.Sprintf("The images are for different architectures, %s and %s; compare two builds for the same one.", b.Architecture, a.Architecture))
	}
	if same(b.ManifestDigest, a.ManifestDigest) || same(b.ImageID, a.ImageID) {
		out = append(out, "Both are the same image, so any difference comes from the vulnerability data or whichphp's rules, not from the image.")
	}
	if before.Version != "" && after.Version != "" && before.Version != after.Version {
		out = append(out, fmt.Sprintf("The reports come from different versions of whichphp, %s and %s; a verdict can change with its rules.", before.Version, after.Version))
	}
	if running != "" {
		for _, r := range []struct {
			side    string
			version string
		}{{"before", before.Version}, {"after", after.Version}} {
			switch r.version {
			case running:
			case "":
				out = append(out, fmt.Sprintf("The %s report doesn't say which version of whichphp made it, so its verdicts may follow other rules than this whichphp %s. Scan the image again to compare under the same rules.", r.side, running))
			default:
				out = append(out, fmt.Sprintf("The %s report was made by whichphp %s, not by this whichphp %s; its verdicts follow the rules of that version, which may have changed since. Scan the image again to compare under the same rules.", r.side, r.version, running))
			}
		}
	}
	return out
}

func same(a, b string) bool { return a != "" && a == b }

// phpNumberRE finds the PHP version in a package name: "8.3" in "php8.3-fpm", "83" in
// "php83-fpm" and "ea-php83-php-fpm", "7" in "libphp7".
var phpNumberRE = regexp.MustCompile(`php\d+(\.\d+)?`)

// family is a build's name without the PHP version in it, so that php8.3-fpm and
// php8.4-fpm are the same build of a newer PHP.
func family(name string) string {
	return phpNumberRE.ReplaceAllString(strings.ToLower(name), "php")
}

// maxBuilds bounds the builds paired one by one, which takes time in the square of
// their number. An image holds a handful; a report file with more is rejected.
const maxBuilds = 1000

// match pairs the PHP builds of two reports. Each pass pairs the builds earlier passes
// left, and where several could pair, the closest PHP versions first, and of those,
// builds of the same source and provider first:
//
//  1. the same name, SAPI and version: unchanged;
//  2. the same name and SAPI;
//  3. the same name apart from the PHP version in it, and the same SAPI
//     (php8.3-fpm and php8.4-fpm);
//  4. the same SAPI, when each image has one build of that SAPI left
//     (libapache2-mod-php8.2 and libphp).
//
// The builds left after that were added or removed.
func match(before, after []verdict.PHP) []Build {
	usedB, usedA := make([]bool, len(before)), make([]bool, len(after))
	out := []Build{}
	pass := func(how string, ok func(b, a verdict.PHP) bool) {
		type candidate struct {
			i, j int
			dist [4]int
			// otherKind is set when the two builds differ in source or provider.
			otherKind bool
		}
		var cands []candidate
		for i, b := range before {
			for j, a := range after {
				if !usedB[i] && !usedA[j] && b.SAPI == a.SAPI && ok(b, a) {
					cands = append(cands, candidate{i, j, distance(b.Version, a.Version), b.Source != a.Source || b.Provider != a.Provider})
				}
			}
		}
		sort.SliceStable(cands, func(x, y int) bool {
			if cands[x].dist != cands[y].dist {
				return closer(cands[x].dist, cands[y].dist)
			}
			return !cands[x].otherKind && cands[y].otherKind
		})
		for _, c := range cands {
			if usedB[c.i] || usedA[c.j] {
				continue
			}
			usedB[c.i], usedA[c.j] = true, true
			out = append(out, paired(how, before[c.i], after[c.j], c.i, c.j))
		}
	}
	left := func(builds []verdict.PHP, used []bool, sapi string) int {
		n := 0
		for i, p := range builds {
			if !used[i] && p.SAPI == sapi {
				n++
			}
		}
		return n
	}
	pass(MatchName, func(b, a verdict.PHP) bool { return b.Name == a.Name && b.Version == a.Version })
	pass(MatchName, func(b, a verdict.PHP) bool { return b.Name == a.Name })
	pass(MatchFamily, func(b, a verdict.PHP) bool { return family(b.Name) == family(a.Name) })
	pass(MatchSAPI, func(b, a verdict.PHP) bool {
		return left(before, usedB, b.SAPI) == 1 && left(after, usedA, a.SAPI) == 1
	})
	for j, a := range after {
		if !usedA[j] {
			out = append(out, Build{Change: Added, After: summarize(a), CVEs: cveChanges(nil, a.CVEs), before: -1, after: j})
		}
	}
	for i, b := range before {
		if !usedB[i] {
			out = append(out, Build{Change: Removed, Before: summarize(b), CVEs: cveChanges(b.CVEs, nil), before: i, after: -1})
		}
	}
	order := map[string]int{Changed: 0, Added: 1, Removed: 2, Unchanged: 3}
	sort.SliceStable(out, func(x, y int) bool {
		a, b := out[x], out[y]
		if order[a.Change] != order[b.Change] {
			return order[a.Change] < order[b.Change]
		}
		if a.Change == Removed {
			return a.before < b.before
		}
		return a.after < b.after
	})
	return out
}

func paired(how string, b, a verdict.PHP, i, j int) Build {
	out := Build{Change: Changed, Match: how, Before: summarize(b), After: summarize(a), CVEs: cveChanges(b.CVEs, a.CVEs), before: i, after: j}
	if b.Name == a.Name && b.Version == a.Version {
		out.Change = Unchanged
	}
	return out
}

func summarize(p verdict.PHP) *PHP {
	return &PHP{Name: p.Name, Version: p.Version, Source: p.Source, Provider: p.Provider, SAPI: p.SAPI}
}

func cveChanges(before, after map[string]verdict.CVEResult) map[string]VerdictChange {
	out := map[string]VerdictChange{}
	for cve, r := range before {
		c := out[cve]
		c.Before = string(r.Verdict)
		if r.Verdict == verdict.FixedByDistroBackport && r.Unconfirmed {
			c.Unconfirmed = &Sides{Before: true}
		}
		out[cve] = c
	}
	for cve, r := range after {
		c := out[cve]
		c.After = string(r.Verdict)
		if r.Verdict == verdict.FixedByDistroBackport && r.Unconfirmed {
			c.Unconfirmed = withAfter(c.Unconfirmed)
		}
		out[cve] = c
	}
	return out
}

// distance says how far apart two PHP versions are: by major, then minor, then patch
// version. A version that can't be read is farther than any that can, unless both are
// the same string.
func distance(a, b string) [4]int {
	if a == b {
		return [4]int{}
	}
	va, okA := phpver.Parse(a)
	vb, okB := phpver.Parse(b)
	if !okA || !okB {
		return [4]int{1}
	}
	ta, tb := va.Triple(), vb.Triple()
	return [4]int{0, absDiff(ta[0], tb[0]), absDiff(ta[1], tb[1]), absDiff(ta[2], tb[2])}
}

func closer(a, b [4]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// absDiff is |a-b| for the non-negative numbers phpver.Parse returns.
func absDiff(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}

// actionLevel orders actions by what they ask for: nothing, a closer look, action.
func actionLevel(a string) int {
	switch verdict.Action(a) {
	case verdict.ActionOK, verdict.ActionNoPHP:
		return 0
	case verdict.ActionNeeded:
		return 2
	}
	return 1
}

// verdictLevel orders verdicts the same way. No verdict, as in an image without PHP,
// asks for nothing; a verdict this version doesn't know counts as uncertain.
func verdictLevel(v string) int {
	switch verdict.Verdict(v) {
	case "", verdict.Fixed, verdict.FixedByDistroBackport, verdict.FixedByVendorBackport, verdict.NotAffected:
		return 0
	case verdict.Vulnerable, verdict.VulnerableEOL:
		return 2
	}
	return 1
}

// mitigated reports whether session.upload_progress.enabled is off, at least where
// FPM serves PHP.
func mitigated(effective string) bool {
	return effective == "off" || effective == "off-in-fpm-pool"
}

func outcome(d Diff) Outcome {
	if !d.phpChanged() {
		return NoPHPChange
	}
	// Finding no PHP proves nothing: a build whichphp doesn't recognize would be missed.
	if d.hasPHP(false) && !d.hasPHP(true) {
		return NoPHPAfter
	}
	before, after := actionLevel(d.Action.Before), actionLevel(d.Action.After)
	switch {
	case after > before:
		return GotWorse
	case after < before && after == 0 && !d.unconfirmedAfter():
		return Fixed
	case after < before:
		return Improved
	}
	worse, better := false, false
	for _, c := range d.Verdicts {
		vb, va := verdictLevel(c.Before), verdictLevel(c.After)
		worse = worse || va > vb
		better = better || va < vb
	}
	worse = worse || mitigated(d.UploadProgress.Before) && d.UploadProgress.After == "on"
	better = better || d.UploadProgress.Before == "on" && mitigated(d.UploadProgress.After)
	switch {
	case worse && !better:
		return GotWorse
	case after == 2:
		return StillVulnerable
	case after == 1:
		return StillUnknown
	}
	return StillOK
}

// hasPHP reports whether whichphp found PHP in the after image, or in the before image.
func (d Diff) hasPHP(after bool) bool {
	for _, b := range d.PHP {
		if after && b.After != nil || !after && b.Before != nil {
			return true
		}
	}
	return false
}

// unconfirmedAfter reports whether a fix in the after image is a distro backport whose
// feed coverage wasn't confirmed.
func (d Diff) unconfirmedAfter() bool {
	for _, b := range d.PHP {
		for _, c := range b.CVEs {
			if b.After != nil && c.Unconfirmed != nil && c.Unconfirmed.After {
				return true
			}
		}
	}
	return false
}

// phpChanged reports whether anything about PHP differs between the two images.
func (d Diff) phpChanged() bool {
	if d.Action.Before != d.Action.After || d.UploadProgress.Before != d.UploadProgress.After {
		return true
	}
	for _, c := range d.Verdicts {
		if c.Before != c.After {
			return true
		}
	}
	for _, b := range d.PHP {
		if b.Change != Unchanged {
			return true
		}
		for _, c := range b.CVEs {
			if c.Before != c.After {
				return true
			}
		}
	}
	return false
}

// cveOrder lists the CVEs in a set of changes: whichphp's own in advisory order, then
// any others, from a report of another version, sorted.
func cveOrder(m map[string]VerdictChange) []string {
	var out, others []string
	for _, c := range advisory.CVEs {
		if _, ok := m[c]; ok {
			out = append(out, c)
		}
	}
	for c := range m {
		known := false
		for _, k := range advisory.CVEs {
			known = known || c == k
		}
		if !known {
			others = append(others, c)
		}
	}
	sort.Strings(others)
	return append(out, others...)
}
