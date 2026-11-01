package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yusufyildiz34/whichphp/internal/advisory"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

type cdxBOM struct {
	Schema          string         `json:"$schema"`
	BOMFormat       string         `json:"bomFormat"`
	SpecVersion     string         `json:"specVersion"`
	SerialNumber    string         `json:"serialNumber"`
	Version         int            `json:"version"`
	Metadata        cdxMetadata    `json:"metadata"`
	Components      []cdxComponent `json:"components"`
	Vulnerabilities []cdxVuln      `json:"vulnerabilities"`
}

type cdxMetadata struct {
	Timestamp string       `json:"timestamp"`
	Tools     cdxTools     `json:"tools"`
	Authors   []cdxContact `json:"authors,omitempty"`
	Component cdxComponent `json:"component"`
}

type cdxContact struct {
	Name string `json:"name"`
}

type cdxTools struct {
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Type               string        `json:"type"`
	BOMRef             string        `json:"bom-ref,omitempty"`
	Name               string        `json:"name"`
	Version            string        `json:"version,omitempty"`
	Hashes             []cdxHash     `json:"hashes,omitempty"`
	PURL               string        `json:"purl,omitempty"`
	ExternalReferences []cdxExtRef   `json:"externalReferences,omitempty"`
	Properties         []cdxProperty `json:"properties,omitempty"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxExtRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxVuln struct {
	BOMRef   string      `json:"bom-ref"`
	ID       string      `json:"id"`
	Source   cdxSource   `json:"source"`
	Ratings  []cdxRating `json:"ratings,omitempty"`
	Analysis cdxAnalysis `json:"analysis"`
	Affects  []cdxAffect `json:"affects"`
}

type cdxSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type cdxRating struct {
	Source   cdxSource `json:"source"`
	Score    float64   `json:"score"`
	Severity string    `json:"severity"`
	Method   string    `json:"method"`
}

type cdxAnalysis struct {
	State         string   `json:"state"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

type cdxAffect struct {
	Ref string `json:"ref"`
}

// cdxHashAlgs names OCI digest algorithms the way CycloneDX does.
var cdxHashAlgs = map[string]string{"sha256": "SHA-256", "sha512": "SHA-512"}

// CycloneDX writes the report as a CycloneDX 1.6 BOM with VEX: the scanned image,
// directory or file as the subject, a component for each PHP, and a vulnerability for
// each CVE whose analysis follows the same evidence rules as OpenVEX. Fixed PHP is
// "resolved" and PHP older than the first affected release is "not_affected", both
// only on positive evidence; vulnerable PHP is "exploitable"; every uncertain case,
// including a source where whichphp found no PHP, is "in_triage".
//
// A vulnerability has one analysis, so a CVE whose PHP builds get different states
// is listed once per build, each entry affecting that build only.
//
// An image is a container named by the same purl OpenVEX uses, when the report has
// one. Unlike OpenVEX, CycloneDX doesn't need a purl, so directories and archives
// without a tag get a BOM too, and an image without a digest is a container with only
// a name. Its analyses keep their states: they are about the PHP components of this
// BOM, whose subject is whatever was scanned, not about an image a consumer could look
// up by name. opt.Author, when set, is named as the BOM's author.
func CycloneDX(w io.Writer, r verdict.Report, opt VEXOptions) error {
	serial, err := newID()
	if err != nil {
		return fmt.Errorf("making a serial number: %w", err)
	}
	refs := bomRefs{}

	what := r.Image.SourceType
	subject := cdxComponent{Type: "file", Name: imageLabel(r)}
	if what == "image" {
		subject.Type, subject.PURL = "container", imagePURL(r)
		if d := strings.ToLower(r.Image.ManifestDigest); digestRE.MatchString(d) {
			alg, sum, _ := strings.Cut(d, ":")
			subject.Hashes = []cdxHash{{Alg: cdxHashAlgs[alg], Content: sum}}
		}
	} else if what != "directory" && what != "file" {
		what = "source"
	}
	ref := subject.PURL
	if ref == "" {
		ref = subject.Name
	}
	subject.BOMRef = refs.add(ref)

	// Sorted, so the BOM doesn't depend on the order Syft listed packages in.
	php := append([]verdict.PHP(nil), r.PHP...)
	sort.SliceStable(php, func(i, j int) bool { return cdxKey(php[i]) < cdxKey(php[j]) })
	comps := []cdxComponent{}
	for _, p := range php {
		purl := phpPURL(p)
		c := cdxComponent{Type: "application", BOMRef: refs.add(purl), Name: p.Name, Version: p.Version, PURL: purl}
		for _, prop := range [][2]string{{"provider", p.Provider}, {"sapi", p.SAPI}, {"source", p.Source}} {
			if prop[1] != "" {
				c.Properties = append(c.Properties, cdxProperty{Name: "whichphp:" + prop[0], Value: prop[1]})
			}
		}
		comps = append(comps, c)
	}

	ids := append([]string(nil), advisory.CVEs...)
	sort.Strings(ids)
	vulns := []cdxVuln{}
	for _, cve := range ids {
		base := cdxVuln{
			ID:      cve,
			Source:  cdxSource{Name: "NVD", URL: "https://nvd.nist.gov/vuln/detail/" + cve},
			Ratings: cdxRatings(cve),
		}
		if len(php) == 0 {
			v := base
			v.BOMRef = refs.add(cve)
			v.Analysis = cdxAnalysis{State: "in_triage", Detail: noPHPNote(what)}
			v.Affects = []cdxAffect{{Ref: subject.BOMRef}}
			vulns = append(vulns, v)
			continue
		}
		// The justification and response follow from the state, so builds in the
		// same state can share one entry.
		analyses := make([]cdxAnalysis, len(php))
		shared := true
		for i, p := range php {
			res := p.CVEs[cve]
			analyses[i] = cdxAnalysisOf(res)
			analyses[i].Detail = phpNote(p, res)
			shared = shared && analyses[i].State == analyses[0].State
		}
		if shared {
			v := base
			v.BOMRef = refs.add(cve)
			v.Analysis = analyses[0]
			details := make([]string, len(php))
			for i, c := range comps {
				details[i] = analyses[i].Detail
				v.Affects = append(v.Affects, cdxAffect{Ref: c.BOMRef})
			}
			v.Analysis.Detail = strings.Join(details, "\n")
			vulns = append(vulns, v)
			continue
		}
		for i, c := range comps {
			v := base
			v.BOMRef = refs.add(cve + "/" + c.BOMRef)
			v.Analysis = analyses[i]
			v.Affects = []cdxAffect{{Ref: c.BOMRef}}
			vulns = append(vulns, v)
		}
	}

	bom := cdxBOM{
		Schema:       "http://cyclonedx.org/schema/bom-1.6.schema.json",
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: serial,
		Version:      1,
		Metadata: cdxMetadata{
			Timestamp: now().UTC().Format(time.RFC3339),
			Tools: cdxTools{Components: []cdxComponent{{
				Type: "application", Name: "whichphp", Version: r.Version,
				ExternalReferences: []cdxExtRef{{Type: "vcs", URL: repoURL}},
			}}},
			Authors:   authors(opt.Author),
			Component: subject,
		},
		Components:      comps,
		Vulnerabilities: vulns,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(bom)
}

// cdxAnalysisOf maps a CVE result to a CycloneDX analysis through its OpenVEX status.
func cdxAnalysisOf(res verdict.CVEResult) cdxAnalysis {
	switch vexStatus(res) {
	case "fixed":
		return cdxAnalysis{State: "resolved"}
	case "not_affected":
		return cdxAnalysis{State: "not_affected", Justification: "code_not_present"}
	case "affected":
		return cdxAnalysis{State: "exploitable", Response: []string{"update"}}
	}
	return cdxAnalysis{State: "in_triage"}
}

// cdxKey orders PHP builds by purl, then by the rest of what their component shows.
func cdxKey(p verdict.PHP) string {
	return strings.Join([]string{phpPURL(p), p.Name, p.Version, p.Type, p.Source, p.Provider, p.SAPI}, "\x00")
}

// cdxRatings is PHP's CVSS v4.0 score for the CVE, or nil when advisory.Severity has
// none.
func cdxRatings(cve string) []cdxRating {
	score, err := strconv.ParseFloat(advisory.Severity[cve], 64)
	if err != nil {
		return nil
	}
	return []cdxRating{{Source: cdxSource{Name: "php.net"}, Score: score, Severity: cvssSeverity(score), Method: "CVSSv4"}}
}

// cvssSeverity is the qualitative rating CVSS v4.0 gives a base score.
func cvssSeverity(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	}
	return "none"
}

// bomRefs hands out bom-refs, which must be unique in a BOM. They are built from
// purls and CVE IDs, and purls come from the image, so two packages can ask for the
// same one; the second gets a numbered one ("...#2"). Refs are made valid UTF-8
// first: JSON output turns every invalid byte into U+FFFD, which would make refs
// that differ here equal in the file.
type bomRefs map[string]bool

func (b bomRefs) add(ref string) string {
	ref = strings.ToValidUTF8(ref, "\uFFFD")
	out := ref
	for n := 2; b[out]; n++ {
		out = ref + "#" + strconv.Itoa(n)
	}
	b[out] = true
	return out
}

func authors(name string) []cdxContact {
	if strings.TrimSpace(name) == "" {
		return nil
	}
	return []cdxContact{{Name: name}}
}
