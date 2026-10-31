package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/yusufyildiz34/whichphp/internal/advisory"
	"github.com/yusufyildiz34/whichphp/internal/phpini"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

// mitigationRule is the SARIF rule for an image whose upload progress setting is on.
const mitigationRule = advisory.MitigationCVE

// unprovenRule is the rule for a CVE whose fix whichphp could neither prove nor
// disprove. It has no security-severity, so code scanning doesn't rate an unknown as
// critical as it would a known vulnerability.
func unprovenRule(cve string) string { return cve + "-unproven" }

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool      `json:"tool"`
	Results    []sarifResult  `json:"results"`
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifRule struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	ShortDescription     sarifText         `json:"shortDescription"`
	FullDescription      sarifText         `json:"fullDescription"`
	HelpURI              string            `json:"helpUri"`
	Help                 sarifText         `json:"help"`
	DefaultConfiguration map[string]string `json:"defaultConfiguration"`
	Properties           map[string]any    `json:"properties"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine int `json:"startLine"`
		} `json:"region"`
	} `json:"physicalLocation"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}

type sarifLogical struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

// SARIF writes the report as SARIF 2.1.0, for GitHub code scanning and similar tools.
// Each PHP binary or package that is vulnerable, or whose status is uncertain, gets one
// result per CVE. An image whose upload progress setting is on gets a result for the
// CVE-2026-115560 mitigation. Fixed and not-affected PHP gets no result.
//
// Text from the image (package names, versions, paths) is escaped, so it can't add
// links or placeholders to a message. Locations are paths inside the image.
func SARIF(w io.Writer, r verdict.Report) error {
	rules := sarifRules()
	index := map[string]int{}
	for i, rule := range rules {
		index[rule.ID] = i
	}
	label, repo := imageLabel(r), imageRepo(r)
	results := []sarifResult{}
	for _, p := range r.PHP {
		where := "/"
		if len(p.Paths) > 0 {
			where = p.Paths[0]
		}
		for _, cve := range advisory.CVEs {
			res := p.CVEs[cve]
			level := sarifLevel(res.Verdict)
			if level == "" {
				continue
			}
			src := p.Source
			if p.Provider != "" {
				src += ", " + p.Provider
			}
			msg := fmt.Sprintf("%s %s (%s, %s) in %s is %s for %s: %s.", p.Name, p.Version, src, p.SAPI, label, res.Verdict, cve, res.Why)
			if res.Verdict.IsVulnerable() {
				msg += " Rebuild or replace the image."
			}
			rule := cve
			if level == "warning" {
				rule = unprovenRule(cve)
			}
			loc := sarifLoc(where)
			loc.LogicalLocations = []sarifLogical{{Name: p.Name, FullyQualifiedName: repo + "/" + p.Name, Kind: "module"}}
			results = append(results, sarifResult{
				RuleID: rule, RuleIndex: index[rule], Level: level,
				Message:   sarifText{Text: sarifEscape(msg)},
				Locations: []sarifLocation{loc},
				// GitHub code scanning only reads primaryLocationLineHash. Leaving out
				// the tag and digest keeps one alert open across rebuilds and per-commit
				// tags until it's fixed; the package name keeps packages that share a
				// location (the dpkg or apk database) apart.
				PartialFingerprints: map[string]string{"primaryLocationLineHash": fingerprint(rule, repo, p.Type, p.Name, where)},
				Properties:          map[string]any{"verdict": res.Verdict, "phpVersion": p.Version, "source": p.Source, "sapi": p.SAPI},
			})
		}
	}
	if s, ok := r.Settings[phpini.UploadProgress]; ok && len(r.PHP) > 0 && (s.Effective == "on" || s.Effective == "unknown") {
		where := "/"
		if len(r.PHP[0].Paths) > 0 {
			where = r.PHP[0].Paths[0]
		}
		level := "warning"
		if s.Effective == "unknown" {
			level = "note" // the image's settings couldn't be read
		}
		results = append(results, sarifResult{
			RuleID: mitigationRule, RuleIndex: index[mitigationRule], Level: level,
			Message: sarifText{Text: sarifEscape(fmt.Sprintf("%s is %s in %s: %s. %s has no fix yet; set %s = 0 server-wide.",
				advisory.MitigationSetting, s.Effective, label, s.Why, advisory.MitigationCVE, advisory.MitigationSetting))},
			Locations:           []sarifLocation{sarifLoc(where)},
			PartialFingerprints: map[string]string{"primaryLocationLineHash": fingerprint(mitigationRule, repo, advisory.MitigationSetting)},
		})
	}

	props := map[string]any{"image": label, "action": r.Action}
	if r.Image.ManifestDigest != "" {
		props["manifestDigest"] = r.Image.ManifestDigest
	}
	if r.Image.Architecture != "" {
		props["architecture"] = r.Image.Architecture
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:       sarifTool{Driver: sarifDriver{Name: "whichphp", Version: r.Version, InformationURI: repoURL, Rules: rules}},
			Results:    results,
			Properties: props,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}

func sarifLevel(v verdict.Verdict) string {
	switch {
	case v.IsVulnerable():
		return "error"
	case v.IsUncertain():
		return "warning"
	}
	return ""
}

// sarifLoc makes a relative, percent-encoded URI from a path inside the image.
func sarifLoc(p string) sarifLocation {
	var l sarifLocation
	p = strings.TrimLeft(p, "/")
	if p == "" {
		p = "."
	}
	l.PhysicalLocation.ArtifactLocation.URI = (&url.URL{Path: p}).EscapedPath()
	l.PhysicalLocation.Region.StartLine = 1
	return l
}

// sarifEscape keeps text from being read as SARIF markup: "[text](target)" links
// and "{0}" placeholders.
var sarifEscaper = strings.NewReplacer("[", `\[`, "]", `\]`, "{", "{{", "}", "}}")

func sarifEscape(s string) string { return sarifEscaper.Replace(s) }

func fingerprint(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:16]) + ":1"
}

func sarifRules() []sarifRule {
	fixed := fixedReleases()
	var rules []sarifRule
	for _, cve := range advisory.CVEs {
		props := map[string]any{"tags": []string{"security", "php", "container", "php2shell"}}
		if score, ok := advisory.Severity[cve]; ok {
			props["security-severity"] = score
		}
		rules = append(rules, sarifRule{
			ID:               cve,
			Name:             "PHPNotFixedFor" + strings.ReplaceAll(strings.TrimPrefix(cve, "CVE-"), "-", "_"),
			ShortDescription: sarifText{Text: "PHP in this image isn't fixed for PHP2Shell (" + cve + ")"},
			FullDescription:  sarifText{Text: cve + " (PHP2Shell) is fixed in PHP " + fixed + ". PHP 8.1 and older get no upstream fix; distros may backport it."},
			HelpURI:          "https://nvd.nist.gov/vuln/detail/" + cve,
			Help: sarifText{
				Text: "Rebuild the image on a base with PHP " + fixed + ", or a distro package that carries the backport, then recreate running containers. Save their logs first.",
				Markdown: "**Fix:** rebuild the image on a base with PHP " + fixed + ", or a distro package that carries the backport, then recreate running containers (save their logs first). " +
					"See [verdicts](" + repoURL + "#verdicts).",
			},
			DefaultConfiguration: map[string]string{"level": "error"},
			Properties:           props,
		})
		rules = append(rules, sarifRule{
			ID:               unprovenRule(cve),
			Name:             "PHPFixUnprovenFor" + strings.ReplaceAll(strings.TrimPrefix(cve, "CVE-"), "-", "_"),
			ShortDescription: sarifText{Text: "whichphp couldn't prove whether PHP in this image is fixed for " + cve},
			FullDescription: sarifText{Text: "The evidence for " + cve + " is inconclusive: a distro package whose feed doesn't cover the CVE, " +
				"a third-party build only its vendor can vouch for, or stale vulnerability data."},
			HelpURI: repoURL + "#verdicts",
			Help: sarifText{
				Text:     "Check with the image's vendor or distro whether the PHP build includes the fix, or rebuild on a base with PHP " + fixed + ".",
				Markdown: "Check with the image's vendor or distro whether the PHP build includes the fix, or rebuild on a base with PHP " + fixed + ". See [verdicts](" + repoURL + "#verdicts).",
			},
			DefaultConfiguration: map[string]string{"level": "warning"},
			Properties:           map[string]any{"tags": []string{"security", "php", "container", "php2shell"}},
		})
	}
	rules = append(rules, sarifRule{
		ID:               mitigationRule,
		Name:             "UploadProgressOn",
		ShortDescription: sarifText{Text: "The " + advisory.MitigationCVE + " mitigation is not applied"},
		FullDescription:  sarifText{Text: advisory.MitigationCVE + " has no fix yet. Until it does, the mitigation is " + advisory.MitigationSetting + " = 0, set server-wide."},
		HelpURI:          "https://nvd.nist.gov/vuln/detail/" + advisory.MitigationCVE,
		Help: sarifText{
			Text:     "Set " + advisory.MitigationSetting + " = 0 in the image's php.ini or conf.d, and in every PHP-FPM pool that overrides it.",
			Markdown: "Set `" + advisory.MitigationSetting + " = 0` in the image's `php.ini` or `conf.d`, and in every PHP-FPM pool that overrides it. Runtime configuration can change it, which whichphp can't see.",
		},
		DefaultConfiguration: map[string]string{"level": "warning"},
		Properties:           map[string]any{"tags": []string{"security", "php", "container", "configuration"}},
	})
	return rules
}

// fixedReleases lists the first fixed release of each branch, newest first, e.g.
// "8.5.12, 8.4.27, 8.3.36 or 8.2.35".
func fixedReleases() string {
	var branches [][2]int
	for b := range advisory.Fixed {
		branches = append(branches, b)
	}
	sort.Slice(branches, func(i, j int) bool {
		if branches[i][0] != branches[j][0] {
			return branches[i][0] > branches[j][0]
		}
		return branches[i][1] > branches[j][1]
	})
	var out []string
	for _, b := range branches {
		v := advisory.Fixed[b]
		out = append(out, fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]))
	}
	if len(out) < 2 {
		return strings.Join(out, "")
	}
	return strings.Join(out[:len(out)-1], ", ") + " or " + out[len(out)-1]
}
