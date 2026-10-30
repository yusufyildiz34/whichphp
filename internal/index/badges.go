package index

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Badge is a shields.io endpoint badge (https://shields.io/badges/endpoint-badge).
type Badge struct {
	SchemaVersion int    `json:"schemaVersion"`
	Label         string `json:"label"`
	Message       string `json:"message"`
	Color         string `json:"color"`
	CacheSeconds  int    `json:"cacheSeconds,omitempty"`
}

// Badge colors, matching the index page.
const (
	colorIndigo = "4b54c9"
	colorRust   = "b93815"
	colorPine   = "0f7a5c"
	colorOchre  = "a86b12"
	colorMuted  = "5f6585"
)

// demoKind marks control tags (exact pre-fix and post-fix releases); badges leave them out.
const demoKind = "demo"

// Badges summarizes the index as shields.io endpoint badges, keyed by file name. The
// counts are per image tag: a tag counts as vulnerable when any of its platforms is.
// Control tags are left out, the same as in the page's summary.
func Badges(idx *Index) map[string]Badge {
	type tag struct{ vulnerable, scanned bool }
	tags := map[string]*tag{}
	builds, uploadOn := 0, 0
	for _, e := range idx.Entries {
		if e.Kind == demoKind {
			continue
		}
		t := tags[e.Ref]
		if t == nil {
			t = &tag{}
			tags[e.Ref] = t
		}
		if e.Error != "" || e.Action == noBuildAction {
			continue
		}
		t.scanned = true
		for _, v := range e.Verdicts {
			if v == "VULNERABLE" || v == "VULNERABLE_EOL" {
				t.vulnerable = true
			}
		}
		if len(e.PHP) > 0 {
			builds++
			if e.UploadProgress == "on" {
				uploadOn++
			}
		}
	}
	scanned, vulnerable := 0, 0
	for _, t := range tags {
		if t.scanned {
			scanned++
		}
		if t.vulnerable {
			vulnerable++
		}
	}

	badge := func(label, message, color string) Badge {
		return Badge{SchemaVersion: 1, Label: label, Message: message, Color: color, CacheSeconds: 3600}
	}
	out := map[string]Badge{
		"tracked.json": badge("images tracked", fmt.Sprintf("%d", len(tags)), colorIndigo),
	}
	if vulnerable > 0 {
		out["vulnerable.json"] = badge("still vulnerable", fmt.Sprintf("%d of %d", vulnerable, scanned), colorRust)
	} else {
		out["vulnerable.json"] = badge("still vulnerable", "none", colorPine)
	}
	if builds > 0 {
		out["upload-progress.json"] = badge("upload progress on", fmt.Sprintf("%d%% of builds", (100*uploadOn+builds/2)/builds), colorOchre)
	} else {
		out["upload-progress.json"] = badge("upload progress on", "no data", colorMuted)
	}
	out["updated.json"] = badge("index updated", day(idx.Generated), colorMuted)
	out["grype-db.json"] = badge("grype db", day(idx.GrypeDBBuilt), colorMuted)
	return out
}

func day(stamp string) string {
	t, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return "unknown"
	}
	return t.UTC().Format("2006-01-02")
}

// SaveBadges writes each badge as dir/<name>.
func SaveBadges(dir string, badges map[string]Badge) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	names := make([]string, 0, len(badges))
	for n := range badges {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b, err := json.Marshal(badges[n])
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, n), append(b, '\n'), 0o644); err != nil {
			return err
		}
	}
	return nil
}
