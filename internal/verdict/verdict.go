// Package verdict turns an SBOM, vulnerability matches and configuration into
// per-CVE verdicts for every PHP found in an image.
package verdict

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/yusufyildiz34/whichphp/internal/advisory"
	"github.com/yusufyildiz34/whichphp/internal/grypejson"
	"github.com/yusufyildiz34/whichphp/internal/phpini"
	"github.com/yusufyildiz34/whichphp/internal/phpver"
	"github.com/yusufyildiz34/whichphp/internal/pkgver"
	"github.com/yusufyildiz34/whichphp/internal/syftjson"
)

// Verdict is the answer for one CVE.
type Verdict string

const (
	Fixed                   Verdict = "FIXED"
	FixedByDistroBackport   Verdict = "FIXED_BY_DISTRO_BACKPORT"
	FixedByVendorBackport   Verdict = "FIXED_BY_VENDOR_BACKPORT"
	Vulnerable              Verdict = "VULNERABLE"
	VulnerableEOL           Verdict = "VULNERABLE_EOL"
	NeedsVendorConfirmation Verdict = "NEEDS_VENDOR_CONFIRMATION"
	Unknown                 Verdict = "UNKNOWN"
	DataStale               Verdict = "DATA_STALE"
	NotAffected             Verdict = "NOT_AFFECTED"
)

var rank = map[Verdict]int{
	VulnerableEOL: 7, Vulnerable: 6, DataStale: 5, Unknown: 5, NeedsVendorConfirmation: 4,
	FixedByDistroBackport: 2, FixedByVendorBackport: 2, Fixed: 1, NotAffected: 0,
}

// IsVulnerable reports whether the verdict calls for action.
func (v Verdict) IsVulnerable() bool { return v == Vulnerable || v == VulnerableEOL }

// IsUncertain reports whether the verdict lacks enough evidence either way.
func (v Verdict) IsUncertain() bool {
	return v == Unknown || v == NeedsVendorConfirmation || v == DataStale
}

// Worse returns the more severe of two verdicts.
func Worse(a, b Verdict) Verdict {
	if a == "" || rank[b] > rank[a] {
		return b
	}
	return a
}

// Install sources.
const (
	SourceUpstream   = "upstream-build"
	SourceDistro     = "distro"
	SourceThirdParty = "third-party"
)

// CVEResult is the verdict for one CVE on one PHP binary or package.
type CVEResult struct {
	Verdict Verdict `json:"verdict"`
	Why     string  `json:"why"`
	Grype   bool    `json:"grypeMatched"`
	// Unconfirmed marks a FIXED_BY_DISTRO_BACKPORT that rests only on the absence of
	// a Grype match, without confirming that the distro's feed covers the CVE.
	Unconfirmed bool `json:"unconfirmed,omitempty"`
}

// PHP is one PHP binary or package found in the image.
type PHP struct {
	Name     string               `json:"name"`
	Version  string               `json:"version"`
	Type     string               `json:"type"`
	PURL     string               `json:"purl,omitempty"`
	Source   string               `json:"source"`
	Provider string               `json:"provider,omitempty"`
	SAPI     string               `json:"sapi"`
	Paths    []string             `json:"paths"`
	CVEs     map[string]CVEResult `json:"cves"`
}

// Distro describes the image's Linux distribution.
type Distro struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Support string `json:"support"`
}

// Image describes what was scanned.
type Image struct {
	Input string `json:"input"`
	// SourceType is Syft's source type: "image", "directory" or "file".
	SourceType string `json:"sourceType,omitempty"`
	// Tags and RepoDigests come from the image metadata. A repo digest
	// (repo@sha256:...) shows which registry the image was pulled from.
	Tags           []string `json:"tags,omitempty"`
	RepoDigests    []string `json:"repoDigests,omitempty"`
	ImageID        string   `json:"imageID,omitempty"`
	ManifestDigest string   `json:"manifestDigest,omitempty"`
	Architecture   string   `json:"architecture,omitempty"`
	Created        string   `json:"created,omitempty"`
	// BuiltBeforeFix is true when the image was created before the fixed releases.
	BuiltBeforeFix *bool  `json:"builtBeforeFix,omitempty"`
	ServingHint    string `json:"servingHint,omitempty"`
}

// Action is the overall outcome, which also sets the exit code.
type Action string

const (
	ActionOK      Action = "OK"
	ActionNeeded  Action = "ACTION_NEEDED"
	ActionUnknown Action = "UNKNOWN"
	ActionNoPHP   Action = "NO_PHP"
)

// ExitCode maps an action to the CLI exit code.
func (a Action) ExitCode() int {
	switch a {
	case ActionNeeded:
		return 1
	case ActionUnknown:
		return 2
	}
	return 0
}

// Report is the full result for one image.
type Report struct {
	Tool     string                    `json:"tool"`
	Version  string                    `json:"version"`
	Image    Image                     `json:"image"`
	Distro   Distro                    `json:"distro"`
	PHP      []PHP                     `json:"php"`
	Verdicts map[string]Verdict        `json:"verdicts"`
	Settings map[string]phpini.Setting `json:"settings"`
	Data     DataInfo                  `json:"data"`
	Action   Action                    `json:"action"`
	Notes    []string                  `json:"notes,omitempty"`
}

// DataInfo records where the vulnerability data came from.
type DataInfo struct {
	GrypeUsed    bool   `json:"grypeUsed"`
	GrypeDBBuilt string `json:"grypeDBBuilt,omitempty"`
	FeedChecked  bool   `json:"feedCoverageChecked"`
}

// Inputs is everything Evaluate needs.
type Inputs struct {
	Doc      *syftjson.Document
	Input    string
	GrypeRan bool
	Hits     map[grypejson.Key][]grypejson.Hit
	DBBuilt  time.Time
	MaxDBAge time.Duration
	Now      time.Time
	// Feed says, per CVE, whether the image's distro security data lists it (from
	// `grype db search --distro`); nil means feed coverage wasn't checked.
	Feed             map[string]grypejson.FeedStatus
	FailOnMitigation bool
	ToolVersion      string
	// ContentCaptured is true when the SBOM was produced with whichphp's config-file
	// globs, so an image with no matching files really has none.
	ContentCaptured bool
}

var (
	debRE = regexp.MustCompile(`^(php\d+(\.\d+)?-(cli|fpm|cgi)|libapache2-mod-php\d+(\.\d+)?)$`)
	apkRE = regexp.MustCompile(`^php\d{0,2}(-fpm|-cgi|-apache2|-embed|-litespeed)?$`)
	rpmRE = regexp.MustCompile(`^(php|php-cli|php-fpm|php-cgi|php\d+-php-(cli|fpm|cgi))$`)
	// cPanel's EasyApache 4 builds, as rpm and deb, and CloudLinux's builds of them.
	// "ea-phpNN-php" holds the Apache module on 5.x and 7.x and is empty on 8.x;
	// "ea-phpNN" and "ea-php-cli" carry no PHP.
	eaRE = regexp.MustCompile(`^ea-php\d{2}-php-(cli|fpm|litespeed)$|^ea-php[57]\d-php$`)
	// CloudLinux's alt-php (PHP Selector, /opt/alt/phpNN), also built as deb by TuxCare.
	// FPM was "alt-phpNN-fpm" before 2025 and is "alt-phpNN-php-fpm" since; every
	// subpackage of a build shares its release.
	altRE = regexp.MustCompile(`^alt-php\d{2}-(cli|fpm|php-fpm)$`)
)

// Find returns the PHP binaries and packages in the SBOM, merged by name and version.
func Find(doc *syftjson.Document) []PHP {
	byKey := map[string]*PHP{}
	var order []string
	for _, a := range doc.Artifacts {
		source := classify(a)
		if source == "" {
			continue
		}
		provider := ""
		if source == SourceDistro {
			if p := thirdParty(a); p != "" {
				source, provider = SourceThirdParty, p
			}
		}
		key := a.Type + "|" + a.Name + "|" + a.Version
		p := byKey[key]
		if p == nil {
			p = &PHP{Name: a.Name, Version: a.Version, Type: a.Type, PURL: a.PURL, Source: source, Provider: provider}
			byKey[key] = p
			order = append(order, key)
		}
		for _, path := range a.Paths() {
			if !contains(p.Paths, path) {
				p.Paths = append(p.Paths, path)
			}
		}
	}
	out := make([]PHP, 0, len(order))
	for _, k := range order {
		p := byKey[k]
		p.SAPI = sapi(p.Name, p.Paths)
		out = append(out, *p)
	}
	return out
}

func classify(a syftjson.Artifact) string {
	switch a.Type {
	case "deb":
		if debRE.MatchString(a.Name) || eaRE.MatchString(a.Name) || altRE.MatchString(a.Name) {
			return SourceDistro
		}
		return ""
	case "apk":
		if apkRE.MatchString(a.Name) {
			return SourceDistro
		}
		return ""
	case "rpm":
		if rpmRE.MatchString(a.Name) || eaRE.MatchString(a.Name) || altRE.MatchString(a.Name) {
			return SourceDistro
		}
		return ""
	case "bitnami":
		if a.Name == "php" || a.Name == "php-fpm" {
			return SourceUpstream
		}
		return ""
	}
	if a.HasCPE(":a:php:php:") {
		return SourceUpstream
	}
	for _, prefix := range []string{"pkg:generic/php@", "pkg:generic/php-cli@", "pkg:generic/php-fpm@", "pkg:generic/php-cgi@"} {
		if strings.HasPrefix(a.PURL, prefix) {
			return SourceUpstream
		}
	}
	return ""
}

// Sury's builds carry "+deb.sury.org+1" on Launchpad (ppa:ondrej/php), a git-buildpackage
// snapshot suffix on packages.sury.org ("+0~20261021.82+debian12~1.gbp4e430a"), and
// "+freexian12.1+php+1" on the temporary arm repository of October 2026.
var suryRE = regexp.MustCompile(`deb\.sury\.org|\+0~\d{8}\.\d+\+(debian|ubuntu)[\d.]+~1\.gbp[0-9a-f]+|\+freexian[\d.]+\+php\+\d+`)

// thirdParty recognizes packages from repositories other than the distro's own, by the
// markers in their versions.
func thirdParty(a syftjson.Artifact) string {
	v := strings.ToLower(a.Version)
	switch {
	case a.Type == "deb" && suryRE.MatchString(v):
		return "Sury"
	// TuxCare's extended support rebuilds a distro's own package, or CloudLinux's alt-php,
	// for releases past their end of life.
	case tuxcareRE.MatchString(v):
		return "TuxCare"
	case a.Type == "deb" && strings.HasPrefix(a.Name, "alt-php"):
		return "TuxCare alt-php"
	case strings.Contains(v, ".remi"):
		return "Remi"
	// GetPageSpeed's releases end in a plain ".el7", like the distro's own; only the
	// rpm Vendor tag tells them apart.
	case a.Type == "rpm" && strings.HasPrefix(a.Metadata.Vendor, "GetPageSpeed"):
		return "GetPageSpeed"
	// CloudLinux builds cPanel's packages under the same names, with epoch 1 and
	// ".elN.cloudlinux" releases that sort above every cPanel build. Its own system PHP
	// carries the same marker in a module release and is numbered differently again.
	case strings.Contains(v, ".cloudlinux") && strings.HasPrefix(a.Name, "ea-php"):
		return "CloudLinux ea-php"
	case strings.Contains(v, ".cloudlinux"):
		return "CloudLinux"
	case strings.Contains(v, ".cpanel"):
		return "cPanel"
	case a.Type == "rpm" && strings.HasPrefix(a.Name, "alt-php"):
		return "CloudLinux alt-php"
	// No distro ships ea-php, so one without a builder's marker comes from a builder
	// whichphp doesn't know, never from the distro's security data.
	case strings.HasPrefix(a.Name, "ea-php"):
		return "ea-php (unknown builder)"
	}
	return ""
}

func sapi(name string, paths []string) string {
	low := strings.ToLower(name + " " + strings.Join(paths, " "))
	switch {
	case strings.Contains(low, "fpm"):
		return "fpm"
	case strings.Contains(low, "libphp") || strings.Contains(low, "apache"),
		strings.HasPrefix(name, "ea-php") && strings.HasSuffix(name, "-php"):
		return "apache-module"
	case strings.Contains(low, "cgi"):
		return "cgi"
	case strings.Contains(low, "litespeed"):
		return "litespeed"
	case strings.Contains(low, "frankenphp"):
		return "embedded"
	}
	return "cli"
}

// ByVersion is the verdict for an upstream PHP version (a source build, or a
// third-party package that ships upstream releases).
func ByVersion(raw string, cve string) (Verdict, string) {
	v, ok := phpver.Parse(raw)
	if !ok {
		return Unknown, fmt.Sprintf("can't read a PHP version from %q", raw)
	}
	t := v.Triple()
	if start, ok := advisory.RangeStart[cve]; ok && phpver.Less(t, start) {
		return NotAffected, fmt.Sprintf("%s is older than the first affected version, %s", v, phpver.FormatTriple(start))
	}
	b := v.Branch()
	pre := advisory.PreReleaseBranch
	if b == pre {
		switch v.Pre {
		case "":
			return Fixed, fmt.Sprintf("%s is a final %d.%d release, which includes the fix", v, b[0], b[1])
		case "rc":
			if v.PreNum >= advisory.FixedRC {
				return Fixed, fmt.Sprintf("%s is RC%d or later, which includes the fix", v, advisory.FixedRC)
			}
			return Vulnerable, fmt.Sprintf("%s predates RC%d, the first %d.%d pre-release with the fix", v, advisory.FixedRC, b[0], b[1])
		case "alpha", "beta":
			return Vulnerable, fmt.Sprintf("%s predates RC%d, the first %d.%d pre-release with the fix", v, advisory.FixedRC, b[0], b[1])
		default:
			return Unknown, fmt.Sprintf("%s is a development snapshot; whether it includes the fix isn't known", v)
		}
	}
	if b[0] > pre[0] || (b[0] == pre[0] && b[1] > pre[1]) {
		return Fixed, fmt.Sprintf("%s is newer than every affected branch", v)
	}
	fixed, ok := advisory.Fixed[b]
	if !ok {
		return VulnerableEOL, fmt.Sprintf("PHP %d.%d is end-of-life and has no upstream fix", b[0], b[1])
	}
	if phpver.Less(t, fixed) {
		return Vulnerable, fmt.Sprintf("%s is older than %s, the first fixed %d.%d release", v, phpver.FormatTriple(fixed), b[0], b[1])
	}
	if v.IsPre() {
		return Unknown, fmt.Sprintf("%s is a pre-release; whether it includes the fix isn't proven", v)
	}
	return Fixed, fmt.Sprintf("%s is %s or later", v, phpver.FormatTriple(fixed))
}

// Reproducible builds give images a placeholder creation date (1970 from Bazel, ko or
// Nix, 1980 from buildpacks) that says nothing about when their packages were installed.
// Docker images date from 2013 on, so an earlier date is taken as no date.
var placeholderDates = time.Date(2013, 1, 1, 0, 0, 0, 0, time.UTC)

// Evaluate builds the report.
func Evaluate(in Inputs) Report {
	doc := in.Doc
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	r := Report{
		Tool:     "whichphp",
		Version:  in.ToolVersion,
		Verdicts: map[string]Verdict{},
		Data:     DataInfo{GrypeUsed: in.GrypeRan, FeedChecked: in.Feed != nil},
	}
	if !in.DBBuilt.IsZero() {
		r.Data.GrypeDBBuilt = in.DBBuilt.UTC().Format(time.RFC3339)
	}

	// Image and distro.
	r.Image.Input = in.Input
	r.Image.SourceType = doc.Source.Type
	md, cfg := doc.Image()
	if md != nil {
		r.Image.Tags, r.Image.RepoDigests = md.Tags, md.RepoDigests
		r.Image.ImageID = md.ImageID
		r.Image.ManifestDigest = md.ManifestDigest
		r.Image.Architecture = md.Architecture
		if r.Image.Input == "" {
			r.Image.Input = md.UserInput
		}
	}
	var builtBeforeFix *bool
	if t, ok := cfg.CreatedTime(); ok {
		r.Image.Created = t.UTC().Format(time.RFC3339)
		if !t.Before(placeholderDates) {
			b := t.Before(advisory.FixReleased)
			builtBeforeFix = &b
			r.Image.BuiltBeforeFix = builtBeforeFix
		}
	}
	if cfg != nil {
		r.Image.ServingHint = servingHint(cfg.Config.Entrypoint, cfg.Config.Cmd)
	}
	support := advisory.Support(doc.Distro.ID, doc.Distro.VersionID)
	r.Distro = Distro{ID: doc.Distro.ID, Version: doc.Distro.VersionID, Support: supportLabel(support)}

	dbStale := in.GrypeRan && !in.DBBuilt.IsZero() && in.MaxDBAge > 0 && in.Now.Sub(in.DBBuilt) > in.MaxDBAge
	if dbStale {
		r.Notes = append(r.Notes, fmt.Sprintf("Grype's database was built %s, more than %s ago. Run `grype db update` for current distro data.",
			in.DBBuilt.UTC().Format("2006-01-02"), in.MaxDBAge))
	}

	// PHP verdicts.
	r.PHP = Find(doc)
	for i := range r.PHP {
		p := &r.PHP[i]
		p.CVEs = map[string]CVEResult{}
		for _, cve := range advisory.CVEs {
			res := judge(*p, cve, in, support, builtBeforeFix, dbStale)
			p.CVEs[cve] = res
			r.Verdicts[cve] = Worse(r.Verdicts[cve], res.Verdict)
		}
	}

	// Settings.
	files := doc.FileContents()
	ini := phpini.Evaluate(files, in.ContentCaptured || len(files) > 0)
	r.Settings = ini.Settings
	is85 := false
	for _, p := range r.PHP {
		if v, ok := phpver.Parse(p.Version); ok && v.Branch() == [2]int{8, 5} {
			is85 = true
		}
	}
	if !is85 {
		delete(r.Settings, phpini.FatalErrorBacktraces)
	}

	// Overall action.
	switch {
	case len(r.PHP) == 0:
		r.Action = ActionNoPHP
		r.Settings = nil
	default:
		r.Action = ActionOK
		for _, v := range r.Verdicts {
			if v.IsVulnerable() {
				r.Action = ActionNeeded
			} else if v.IsUncertain() && r.Action == ActionOK {
				r.Action = ActionUnknown
			}
		}
		if s, ok := r.Settings[phpini.UploadProgress]; ok && s.Effective == "on" {
			r.Notes = append(r.Notes, fmt.Sprintf("%s is on by default in this image. Until PHP fixes %s, turn it off server-wide.",
				advisory.MitigationSetting, advisory.MitigationCVE))
			if in.FailOnMitigation {
				r.Action = ActionNeeded
			}
		}
	}
	return r
}

func judge(p PHP, cve string, in Inputs, support advisory.DistroSupport, builtBeforeFix *bool, dbStale bool) CVEResult {
	hits := in.Hits[grypejson.Key{Name: p.Name, Version: p.Version}]
	var hit *grypejson.Hit
	for i := range hits {
		if hits[i].CVE == cve {
			hit = &hits[i]
		}
	}
	res := CVEResult{Grype: hit != nil}

	switch p.Source {
	case SourceUpstream:
		res.Verdict, res.Why = ByVersion(p.Version, cve)
		return res
	case SourceThirdParty:
		res.Verdict, res.Why = byPackager(p, cve, distroKey(in.Doc.Distro), builtBeforeFix != nil && *builtBeforeFix)
		return res
	}

	// Distro package.
	base, baseWhy := ByVersion(p.Version, cve)
	distro := strings.TrimSpace(in.Doc.Distro.ID + " " + in.Doc.Distro.VersionID)
	ext, extended := extendedBackport(p, cve, distroKey(in.Doc.Distro))
	switch {
	case base == Fixed || base == NotAffected:
		res.Verdict, res.Why = base, baseWhy
	case extended && pkgCompare(p.Type)(p.Version, ext.Fixed) >= 0:
		res.Verdict = FixedByVendorBackport
		res.Why = fmt.Sprintf("version %s looks old, but it is %s or later, %s's build with the fix for %s (%s)",
			p.Version, ext.Fixed, ext.Packager, nonEmpty(distro, "this distro"), ext.Source)
	case hit != nil:
		res.Verdict = Vulnerable
		res.Why = fmt.Sprintf("the %s security data lists this package as affected", nonEmpty(distro, "distro"))
		if len(hit.FixVersions) > 0 {
			res.Why += "; fixed in " + strings.Join(hit.FixVersions, ", ")
		} else {
			res.Why += "; no distro fix yet"
		}
	case extended && support == advisory.EndOfLife:
		res.Verdict = VulnerableEOL
		res.Why = fmt.Sprintf("%s is end-of-life, and this build is older than %s, %s's first build with the fix (%s)",
			distro, ext.Fixed, ext.Packager, ext.Source)
	case support == advisory.EndOfLife && builtBeforeFix != nil && *builtBeforeFix:
		res.Verdict = VulnerableEOL
		res.Why = fmt.Sprintf("%s is end-of-life, so its security data no longer covers this package, and the image predates the fix", distro)
	case support == advisory.EndOfLife:
		res.Verdict = Unknown
		res.Why = fmt.Sprintf("%s is end-of-life; only a vendor backport could include the fix", distro)
	case !in.GrypeRan:
		res.Verdict = Unknown
		res.Why = "distro package; checking backports needs Grype's database (run without --no-grype)"
	case !advisory.DistroFeeds[in.Doc.Distro.ID]:
		res.Verdict = Unknown
		res.Why = fmt.Sprintf("no known security data for distro %q", nonEmpty(in.Doc.Distro.ID, "unknown"))
	default:
		st, checked := in.Feed[cve]
		switch {
		case in.Feed != nil && checked && !st.Listed:
			res.Verdict = NeedsVendorConfirmation
			res.Why = fmt.Sprintf("the %s security data in Grype's database doesn't list %s, so the absence of a match proves nothing", distro, cve)
		case checked && st.Listed:
			res.Verdict = FixedByDistroBackport
			res.Why = fmt.Sprintf("version %s looks old, but the %s security data lists %s and has no open match for it", p.Version, distro, cve)
			if st.FixVersion != "" {
				res.Why += fmt.Sprintf(" (fixed in %s)", st.FixVersion)
			}
		default:
			res.Verdict, res.Unconfirmed = FixedByDistroBackport, true
			res.Why = fmt.Sprintf("version %s looks old, but the %s security data has no open match for it (feed coverage not checked)", p.Version, distro)
		}
		if dbStale {
			res.Verdict, res.Unconfirmed = DataStale, false
			res.Why += "; Grype's database is out of date"
		}
	}
	if extended && (res.Verdict.IsVulnerable() || res.Verdict.IsUncertain()) && !strings.Contains(res.Why, ext.Fixed) {
		res.Why += fmt.Sprintf("; %s has a build with the fix, %s or later (%s)", ext.Packager, ext.Fixed, ext.Source)
	}
	return res
}

// distroKey names a distro release the way packagers.csv does, for example "debian 10".
func distroKey(d syftjson.Distro) string {
	return strings.TrimSpace(d.ID + " " + advisory.NormalizeRelease(d.ID, d.VersionID))
}

// pkgCompare returns the version order of a package format, or nil for formats that
// packagers.csv doesn't cover.
func pkgCompare(typ string) func(a, b string) int {
	switch typ {
	case "deb":
		return pkgver.CompareDeb
	case "rpm":
		return pkgver.CompareRPM
	}
	return nil
}

// Packagers that extend a distro release's support after the distro's own ends, with
// builds that carry no marker of their own. Their packagers.csv rows are scoped to a
// distro release, and a build at or above the row's version can only have come from them.
var distroExtenders = map[string]bool{"Freexian ELTS": true}

// debianUpdateRE finds Debian's stable-update counter, "deb11u" in "7.4.33-1+deb11u14".
var debianUpdateRE = regexp.MustCompile(`deb\d+u`)

// sameDebianLine reports whether an installed version continues the same Debian package
// line as a fixed one: the same text up to the stable-update counter, "7.4.33-1+deb11u".
func sameDebianLine(installed, fixed string) bool {
	loc := debianUpdateRE.FindStringIndex(fixed)
	if loc == nil {
		return true
	}
	return strings.HasPrefix(strings.TrimPrefix(installed, "0:"), strings.TrimPrefix(fixed[:loc[1]], "0:"))
}

// extendedBackport finds the first fixed build of a distro package from a packager that
// extends the distro's support. A row applies only to versions in the same numbering
// as its own: another repository's build of the branch, if it went unrecognized, could
// sort above the row and look fixed.
func extendedBackport(p PHP, cve, distro string) (advisory.Backport, bool) {
	v, ok := phpver.Parse(p.Version)
	cmp := pkgCompare(p.Type)
	if !ok || cmp == nil {
		return advisory.Backport{}, false
	}
	var first advisory.Backport
	found := false
	for _, b := range advisory.Backports {
		if !distroExtenders[b.Packager] || b.Distro != distro || b.Branch != v.Branch() || b.Fixed == "" || !b.Fixes(cve) {
			continue
		}
		if !sameDebianLine(p.Version, b.Fixed) || pkgver.CompareEpoch(p.Version, b.Fixed) > 0 {
			continue
		}
		if !found || cmp(b.Fixed, first.Fixed) < 0 {
			first, found = b, true
		}
	}
	return first, found
}

// elTagRE finds the EL dist tag in a release, "el8" in "2.el8.cloudlinux.1".
var elTagRE = regexp.MustCompile(`\.(el\d+)\.`)

// fixedFor returns a row's first fixed release for the installed version. A row can
// write the EL dist tag as "{el}" when the fix shows only after it: "2.el8.cloudlinux.1"
// is fixed and "2.el8.cloudlinux" isn't, and a row with a fixed tag would rank el9's
// unfixed build above el8's fixed one. A version without a tag can't be compared.
func fixedFor(row advisory.Backport, version string) (string, bool) {
	if !strings.Contains(row.Fixed, "{el}") {
		return row.Fixed, true
	}
	m := elTagRE.FindStringSubmatch(version)
	if m == nil {
		return "", false
	}
	return strings.ReplaceAll(row.Fixed, "{el}", m[1]), true
}

// Packagers whose builds of branches PHP still supports are upstream releases. The
// others, and all of them on end-of-life branches, backport fixes without changing the
// PHP version.
var rebasesSupported = map[string]bool{"Sury": true, "Remi": true, "cPanel": true, "GetPageSpeed": true}

// byPackager judges a third-party build: by its upstream version where that settles it,
// otherwise by the packager's first fixed build in packagers.csv. builtBeforeFix says
// the image was created before the fixed releases, so it can't hold a backport either.
func byPackager(p PHP, cve, distro string, builtBeforeFix bool) (Verdict, string) {
	base, why := ByVersion(p.Version, cve)
	v, ok := phpver.Parse(p.Version)
	if !ok || base == Fixed || base == NotAffected {
		return base, fmt.Sprintf("%s build: %s", p.Provider, why)
	}
	b := v.Branch()
	cmp := packagerOrder(p.Provider, pkgCompare(p.Type))
	var first advisory.Backport
	found, exact, noFix := false, false, ""
	for _, row := range rowsFor(p.Provider, b, distro) {
		if row.Fixed == "" {
			noFix = row.Source
			continue
		}
		fixed, ok := fixedFor(row, p.Version)
		same, sameBuild := sameLine(p.Provider, p.Version, fixed)
		switch {
		case !ok || cmp == nil || !row.Fixes(cve) || !same:
		// A build with a higher epoch than the row's comes from another line, or the row
		// lacks the epoch; either way the row doesn't order it.
		case pkgver.CompareEpoch(p.Version, fixed) > 0:
		// The row for the build's own distro build comes first, then the lowest.
		case !found || (sameBuild && !exact) || (sameBuild == exact && cmp(fixed, first.Fixed) < 0):
			row.Fixed = fixed
			first, found, exact = row, true, sameBuild
		}
	}
	switch {
	// Fixed only on the row's own distro build; another build of the same stream can
	// only show that a build is older.
	case found && exact && cmp(p.Version, first.Fixed) >= 0:
		return FixedByVendorBackport, fmt.Sprintf("version %s looks old, but %s backported the fix into %s and later builds (%s)",
			v, p.Provider, first.Fixed, first.Source)
	case found && cmp(p.Version, first.Fixed) < 0:
		return Vulnerable, fmt.Sprintf("%s's first PHP %d.%d build with the fix is %s; this build is older (%s)",
			p.Provider, b[0], b[1], first.Fixed, first.Source)
	case noFix != "":
		return base, fmt.Sprintf("%s; %s published no fix for PHP %d.%d (%s)", why, p.Provider, b[0], b[1], noFix)
	case builtBeforeFix && base == VulnerableEOL:
		return base, fmt.Sprintf("%s; the image predates the fix, so it can't hold a %s backport either", why, p.Provider)
	case base == VulnerableEOL || !rebasesSupported[p.Provider]:
		return NeedsVendorConfirmation, fmt.Sprintf("%s backports fixes without changing the PHP version, and whichphp has no data on which of its PHP %d.%d builds fix %s; check the package changelog for the CVE ID",
			p.Provider, b[0], b[1], cve)
	}
	return base, fmt.Sprintf("%s ships upstream PHP %d.%d releases: %s", p.Provider, b[0], b[1], why)
}

// rowsFor returns the rows for a packager's build. Rows for the build's distro release,
// "none" rows included, replace the general ones: the general rows describe other
// releases' builds.
func rowsFor(packager string, branch [2]int, distro string) []advisory.Backport {
	rows := advisory.BackportsFor(packager, branch, distro)
	var scoped []advisory.Backport
	for _, r := range rows {
		if r.Distro != "" {
			scoped = append(scoped, r)
		}
	}
	if len(scoped) > 0 {
		return scoped
	}
	return rows
}

// packagerOrder returns how a packager's builds sort. TuxCare's builds of one line differ
// in its own counter after the marker, which alone orders them.
func packagerOrder(provider string, cmp func(a, b string) int) func(a, b string) int {
	if provider != "TuxCare" || cmp == nil {
		return cmp
	}
	return func(a, b string) int {
		ta, _ := parseTuxCare(a)
		tb, _ := parseTuxCare(b)
		return pkgver.CompareRPM(ta.counter, tb.counter)
	}
}

// tuxcareRE finds TuxCare's marker, which follows the release of the distro build it
// rebuilt: "5.4.16-48.el7.tuxcare.els21", "7.4.33-1+deb11u12+tuxcare.els2".
var tuxcareRE = regexp.MustCompile(`[.+]tuxcare\.`)

// tuxcareBuildRE splits a TuxCare build into the distro build it rebuilt, the counter's
// scheme ("els", or "ol.els" for Oracle Linux) and the counter.
var tuxcareBuildRE = regexp.MustCompile(`^(?:0:)?(.+)[.+]tuxcare\.((?:ol\.)?els)(\d+)$`)

// moduleBuildRE finds an EL8 module build's counter and hash, which every rebuild of a
// module stream changes: "+2709+673b459a" in "1.module_el8.5.0+2709+673b459a".
var moduleBuildRE = regexp.MustCompile(`\+\d+\+[0-9a-f]+`)

type tuxcareBuild struct{ base, scheme, counter string }

func parseTuxCare(v string) (tuxcareBuild, bool) {
	m := tuxcareBuildRE.FindStringSubmatch(v)
	if m == nil {
		return tuxcareBuild{}, false
	}
	return tuxcareBuild{m[1], m[2], m[3]}, true
}

// sameLine reports whether an installed build is on the line of a row's fixed build, and
// whether it is the same distro build. TuxCare numbers each distro build it extends on
// its own, and one distro key can cover several (CentOS 8.4 and 8.5, AlmaLinux 9.2 and
// 9.6), so its rows apply only to builds of the same distro release. An EL8 module
// stream changes its module build with every rebuild: a build of the same stream with
// another module build is on the line, but only the same distro build can show it fixed,
// in case two lines differ only there. A counter in any other scheme can't be ordered.
func sameLine(provider, installed, fixed string) (same, sameBuild bool) {
	if provider != "TuxCare" {
		return true, true
	}
	i, ok1 := parseTuxCare(installed)
	f, ok2 := parseTuxCare(fixed)
	if !ok1 || !ok2 || i.scheme != f.scheme {
		return false, false
	}
	if i.base == f.base {
		return true, true
	}
	return moduleBuildRE.ReplaceAllString(i.base, "") == moduleBuildRE.ReplaceAllString(f.base, ""), false
}

func servingHint(entrypoint, cmd []string) string {
	s := strings.ToLower(strings.Join(append(append([]string{}, entrypoint...), cmd...), " ")) + " "
	if strings.TrimSpace(s) == "" {
		return ""
	}
	for _, h := range []struct{ pat, label string }{
		{"php-fpm", "php-fpm"}, {"apache2-foreground", "apache mod_php"}, {"httpd", "apache mod_php"},
		{"apache2", "apache mod_php"}, {"frankenphp", "frankenphp"}, {"rr ", "roadrunner"},
		{"/init", "supervised (s6)"}, {"supervisord", "supervised"}, {"php", "php cli or other"},
	} {
		if strings.Contains(s, h.pat) {
			return h.label
		}
	}
	return "unknown"
}

func supportLabel(s advisory.DistroSupport) string {
	switch s {
	case advisory.Supported:
		return "supported"
	case advisory.EndOfLife:
		return "end-of-life"
	}
	return "unknown"
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
