// Package grypejson reads Grype's JSON output: matches, database status and
// database search results.
package grypejson

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Hit is a Grype match for one of the CVEs whichphp tracks.
type Hit struct {
	CVE         string
	Namespace   string
	FixVersions []string
	FixState    string
	MatchedBy   string
}

// Key identifies an artifact by name and version, as Grype reports it.
type Key struct{ Name, Version string }

type matchDoc struct {
	Matches []struct {
		Vulnerability struct {
			ID        string `json:"id"`
			Namespace string `json:"namespace"`
			Fix       struct {
				Versions []string `json:"versions"`
				State    string   `json:"state"`
			} `json:"fix"`
		} `json:"vulnerability"`
		RelatedVulnerabilities []struct {
			ID string `json:"id"`
		} `json:"relatedVulnerabilities"`
		MatchDetails []struct {
			Type    string `json:"type"`
			Matcher string `json:"matcher"`
		} `json:"matchDetails"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"artifact"`
	} `json:"matches"`
}

// LoadMatches reads `grype -o json` output and returns hits for the given CVEs.
func LoadMatches(path string, cves []string) (map[Key][]Hit, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseMatches(b, cves)
}

// ParseMatches decodes Grype JSON and returns hits for the given CVEs, keyed by artifact.
func ParseMatches(b []byte, cves []string) (map[Key][]Hit, error) {
	var d matchDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("not Grype JSON output: %w", err)
	}
	want := map[string]bool{}
	for _, c := range cves {
		want[c] = true
	}
	out := map[Key][]Hit{}
	for _, m := range d.Matches {
		ids := []string{m.Vulnerability.ID}
		for _, r := range m.RelatedVulnerabilities {
			ids = append(ids, r.ID)
		}
		matcher := ""
		if len(m.MatchDetails) > 0 {
			matcher = m.MatchDetails[0].Type
		}
		seen := map[string]bool{}
		for _, id := range ids {
			if !want[id] || seen[id] {
				continue
			}
			seen[id] = true
			k := Key{m.Artifact.Name, m.Artifact.Version}
			out[k] = append(out[k], Hit{
				CVE:         id,
				Namespace:   m.Vulnerability.Namespace,
				FixVersions: m.Vulnerability.Fix.Versions,
				FixState:    m.Vulnerability.Fix.State,
				MatchedBy:   matcher,
			})
		}
	}
	return out, nil
}

// Status is `grype db status -o json` output.
type Status struct {
	SchemaVersion string    `json:"schemaVersion"`
	From          string    `json:"from"`
	Built         time.Time `json:"built"`
	Path          string    `json:"path"`
	Error         string    `json:"error"`
}

// ParseStatus decodes `grype db status -o json` output.
func ParseStatus(b []byte) (*Status, error) {
	var s Status
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// FeedEntry says a distro feed lists a CVE for a package, with its fix if known.
type FeedEntry struct {
	OS, OSVersion, Package, FixVersion, FixState, Namespace string
}

// FeedStatus says whether a distro's security data lists a CVE.
type FeedStatus struct {
	Listed     bool
	FixVersion string
	Package    string
}

// ParseSearch reads `grype db search --vuln <id> -o json` output. The format has changed
// between Grype releases, so this walks the JSON loosely: it collects every object that
// has an "os" entry, and reads the package name and fix from around it.
func ParseSearch(b []byte) ([]FeedEntry, error) {
	var root any
	if err := json.Unmarshal(b, &root); err != nil {
		return nil, err
	}
	var out []FeedEntry
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			osv, hasOS := t["os"].(map[string]any)
			ns := str(t["namespace"])
			if hasOS || strings.Contains(ns, ":distro:") {
				e := FeedEntry{Namespace: ns}
				if hasOS {
					e.OS, e.OSVersion = str(osv["name"]), str(osv["version"])
				} else if parts := strings.Split(ns, ":"); len(parts) >= 4 {
					// provider:distro:name:version
					e.OS, e.OSVersion = parts[2], parts[3]
				}
				if p, ok := t["package"].(map[string]any); ok {
					e.Package = str(p["name"])
				}
				e.FixVersion, e.FixState = findFix(t["detail"])
				out = append(out, e)
				return
			}
			for _, child := range t {
				walk(child)
			}
		case []any:
			for _, child := range t {
				walk(child)
			}
		}
	}
	walk(root)
	return out, nil
}

func findFix(v any) (version, state string) {
	var walk func(v any)
	walk = func(v any) {
		if version != "" {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			if f, ok := t["fix"].(map[string]any); ok {
				version, state = str(f["version"]), str(f["state"])
				return
			}
			for _, c := range t {
				walk(c)
			}
		case []any:
			for _, c := range t {
				walk(c)
			}
		}
	}
	walk(v)
	return
}

func str(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}
