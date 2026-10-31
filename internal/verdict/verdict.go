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
	"github.com/yusufyildiz34/whichphp/internal/syftjson"
)

// Verdict is the answer for one CVE.
type Verdict string

const (
	Fixed                   Verdict = "FIXED"
	FixedByDistroBackport   Verdict = "FIXED_BY_DISTRO_BACKPORT"
	Vulnerable              Verdict = "VULNERABLE"
	VulnerableEOL           Verdict = "VULNERABLE_EOL"
	NeedsVendorConfirmation Verdict = "NEEDS_VENDOR_CONFIRMATION"
	Unknown                 Verdict = "UNKNOWN"
	DataStale               Verdict = "DATA_STALE"
	NotAffected             Verdict = "NOT_AFFECTED"
)

var rank = map[Verdict]int{
	VulnerableEOL: 7, Vulnerable: 6, DataStale: 5, Unknown: 5, NeedsVendorConfirmation: 4,
	FixedByDistroBackport: 2, Fixed: 1, NotAffected: 0,
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
		if debRE.MatchString(a.Name) {
			return SourceDistro
		}
		return ""
	case "apk":
		if apkRE.MatchString(a.Name) {
			return SourceDistro
		}
		return ""
	case "rpm":
		if rpmRE.MatchString(a.Name) {
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

// thirdParty recognizes packages from repositories that ship upstream PHP releases
// rather than backporting fixes.
func thirdParty(a syftjson.Artifact) string {
	v := strings.ToLower(a.Version)
	switch {
	case strings.Contains(v, "deb.sury.org"):
		return "Sury"
	case strings.Contains(v, ".remi"):
		return "Remi"
	}
	return ""
}

func sapi(name string, paths []string) string {
	low := strings.ToLower(name + " " + strings.Join(paths, " "))
	switch {
	case strings.Contains(low, "fpm"):
		return "fpm"
	case strings.Contains(low, "libphp") || strings.Contains(low, "apache"):
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
		b := t.Before(advisory.FixReleased)
		builtBeforeFix = &b
		r.Image.BuiltBeforeFix = builtBeforeFix
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
		v, why := ByVersion(p.Version, cve)
		res.Verdict, res.Why = v, fmt.Sprintf("%s ships upstream PHP releases: %s", p.Provider, why)
		return res
	}

	// Distro package.
	base, baseWhy := ByVersion(p.Version, cve)
	distro := strings.TrimSpace(in.Doc.Distro.ID + " " + in.Doc.Distro.VersionID)
	switch {
	case base == Fixed || base == NotAffected:
		res.Verdict, res.Why = base, baseWhy
	case hit != nil:
		res.Verdict = Vulnerable
		res.Why = fmt.Sprintf("the %s security data lists this package as affected", nonEmpty(distro, "distro"))
		if len(hit.FixVersions) > 0 {
			res.Why += "; fixed in " + strings.Join(hit.FixVersions, ", ")
		} else {
			res.Why += "; no distro fix yet"
		}
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
	return res
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
