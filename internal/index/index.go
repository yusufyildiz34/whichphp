// Package index maintains the public index: for each tracked image tag and platform, the
// PHP inside, the verdicts, and when the tag first carried the fix.
//
// Each run checks every tag's manifest digest with a cheap HEAD request and rescans only
// what changed, what was never scanned, what failed last time, or what hasn't been
// scanned for a while (distro security data can change without a new image).
package index

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/yusufyildiz34/whichphp/internal/phpini"
	"github.com/yusufyildiz34/whichphp/internal/registry"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

const (
	noBuild       = "no build for this platform"
	noBuildAction = "NO_BUILD"
)

// SchemaVersion is bumped when the index format changes incompatibly.
const SchemaVersion = 1

// Image is one tracked image tag.
type Image struct {
	Ref   string `json:"ref"`
	Kind  string `json:"kind,omitempty"`
	Owner string `json:"owner,omitempty"`
	Note  string `json:"note,omitempty"`
}

// PHP summarizes one PHP binary or package in an indexed image.
type PHP struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Source   string `json:"source"`
	Provider string `json:"provider,omitempty"`
	SAPI     string `json:"sapi"`
}

// Entry is the indexed state of one tag on one platform.
type Entry struct {
	Ref      string `json:"ref"`
	Platform string `json:"platform"`
	Kind     string `json:"kind,omitempty"`
	Owner    string `json:"owner,omitempty"`
	Note     string `json:"note,omitempty"`

	TagDigest   string `json:"tagDigest,omitempty"`
	ImageDigest string `json:"imageDigest,omitempty"`
	CheckedAt   string `json:"checkedAt"`
	ScannedAt   string `json:"scannedAt,omitempty"`

	ImageCreated   string            `json:"imageCreated,omitempty"`
	BuiltBeforeFix *bool             `json:"builtBeforeFix,omitempty"`
	Distro         string            `json:"distro,omitempty"`
	PHP            []PHP             `json:"php,omitempty"`
	Verdicts       map[string]string `json:"verdicts,omitempty"`
	UploadProgress string            `json:"uploadProgress,omitempty"`
	Action         string            `json:"action,omitempty"`

	// FirstFixedDigest and FirstFixedSeen record when the index first saw this tag move
	// from ACTION_NEEDED to OK.
	FirstFixedDigest string `json:"firstFixedDigest,omitempty"`
	FirstFixedSeen   string `json:"firstFixedSeen,omitempty"`

	Error string `json:"error,omitempty"`
}

// Key identifies an entry.
func (e Entry) Key() string { return e.Ref + "|" + e.Platform }

// Index is the whole published index.
type Index struct {
	Schema       int      `json:"schema"`
	Generated    string   `json:"generated"`
	Tool         string   `json:"tool"`
	GrypeDBBuilt string   `json:"grypeDBBuilt,omitempty"`
	Notes        []string `json:"notes,omitempty"`
	Entries      []Entry  `json:"entries"`
}

// Change is one line of history: a tag's digest, action or verdicts changed.
type Change struct {
	Time       string            `json:"time"`
	Ref        string            `json:"ref"`
	Platform   string            `json:"platform"`
	FromDigest string            `json:"fromDigest,omitempty"`
	ToDigest   string            `json:"toDigest,omitempty"`
	FromAction string            `json:"fromAction,omitempty"`
	ToAction   string            `json:"toAction,omitempty"`
	Verdicts   map[string]string `json:"verdicts,omitempty"`
}

// Resolver returns the digest a tag points to.
type Resolver func(ctx context.Context, ref string) (string, error)

// Scanner scans one tag on one platform.
type Scanner func(ctx context.Context, ref, platform string) (verdict.Report, error)

// Options control an update run.
type Options struct {
	Platforms   []string
	RescanAfter time.Duration
	// MaxScans bounds the number of image scans per run (0 means no limit). Work that
	// doesn't fit waits for the next run, most urgent first.
	MaxScans int
	Now      func() time.Time
	Log      io.Writer
	Tool     string
}

// LoadImages reads the tracked-image list: CSV with a "ref,kind,owner,note" header;
// blank lines and lines starting with "#" are ignored.
func LoadImages(path string) ([]Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		lines = append(lines, l)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	r := csv.NewReader(strings.NewReader(strings.Join(lines, "\n")))
	r.FieldsPerRecord = -1
	recs, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	var out []Image
	seen := map[string]bool{}
	for i, rec := range recs {
		if i == 0 && len(rec) > 0 && rec[0] == "ref" {
			continue
		}
		img := Image{Ref: strings.TrimSpace(rec[0])}
		if len(rec) > 1 {
			img.Kind = strings.TrimSpace(rec[1])
		}
		if len(rec) > 2 {
			img.Owner = strings.TrimSpace(rec[2])
		}
		if len(rec) > 3 {
			img.Note = strings.TrimSpace(rec[3])
		}
		if img.Ref == "" || seen[img.Ref] {
			continue
		}
		seen[img.Ref] = true
		out = append(out, img)
	}
	return out, nil
}

// Load reads an index; a missing file yields an empty index.
func Load(path string) (*Index, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Index{Schema: SchemaVersion}, nil
	}
	if err != nil {
		return nil, err
	}
	var idx Index
	if err := json.Unmarshal(b, &idx); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if idx.Schema != SchemaVersion {
		return nil, fmt.Errorf("%s: schema %d, want %d", path, idx.Schema, SchemaVersion)
	}
	return &idx, nil
}

// Save writes the index as indented JSON.
func Save(path string, idx *Index) error {
	b, err := json.MarshalIndent(idx, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// AppendHistory appends changes to a JSON Lines file.
func AppendHistory(path string, changes []Change) error {
	if len(changes) == 0 {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, c := range changes {
		if err := enc.Encode(c); err != nil {
			return err
		}
	}
	return nil
}

type job struct {
	img      Image
	platform string
	digest   string
	prev     *Entry
	priority int // lower runs first
	since    time.Time
}

// Update produces the next index from the previous one.
func Update(ctx context.Context, images []Image, prev *Index, resolve Resolver, scan Scanner, opt Options) (*Index, []Change) {
	now := time.Now
	if opt.Now != nil {
		now = opt.Now
	}
	logf := func(format string, a ...any) {
		if opt.Log != nil {
			fmt.Fprintf(opt.Log, format+"\n", a...)
		}
	}
	stamp := now().UTC().Format(time.RFC3339)
	old := map[string]Entry{}
	if prev != nil {
		for _, e := range prev.Entries {
			old[e.Key()] = e
		}
	}
	next := &Index{Schema: SchemaVersion, Generated: stamp, Tool: opt.Tool}
	if prev != nil {
		next.GrypeDBBuilt = prev.GrypeDBBuilt
	}
	entries := map[string]Entry{}
	var jobs []job
	rateLimited := false

	for _, img := range images {
		var digest string
		var resolveErr error
		if !rateLimited {
			digest, resolveErr = resolve(ctx, img.Ref)
			if errors.Is(resolveErr, registry.ErrRateLimited) {
				rateLimited = true
				next.Notes = append(next.Notes, "The registry rate limit was reached; some tags were not checked in this run.")
			}
		}
		for _, platform := range opt.Platforms {
			key := img.Ref + "|" + platform
			p, had := old[key]
			var pp *Entry
			if had {
				pp = &p
			}
			if rateLimited || resolveErr != nil {
				// Keep what we had; record the error only on entries we can't vouch for.
				if had {
					entries[key] = p
				} else if resolveErr != nil && !rateLimited {
					entries[key] = Entry{Ref: img.Ref, Platform: platform, Kind: img.Kind, Owner: img.Owner, Note: img.Note,
						CheckedAt: stamp, Error: resolveErr.Error()}
				}
				continue
			}
			j := job{img: img, platform: platform, digest: digest, prev: pp}
			switch {
			case !had:
				j.priority = 1
			case p.TagDigest != digest:
				j.priority = 0
			case p.Error != "":
				j.priority = 2
			default:
				scanned, _ := time.Parse(time.RFC3339, p.ScannedAt)
				j.since = scanned
				if opt.RescanAfter > 0 && now().Sub(scanned) >= opt.RescanAfter {
					j.priority = 3
				} else {
					p.CheckedAt = stamp
					entries[key] = p
					continue
				}
			}
			jobs = append(jobs, j)
		}
	}

	sort.SliceStable(jobs, func(a, b int) bool {
		if jobs[a].priority != jobs[b].priority {
			return jobs[a].priority < jobs[b].priority
		}
		return jobs[a].since.Before(jobs[b].since)
	})

	var changes []Change
	for i, j := range jobs {
		key := j.img.Ref + "|" + j.platform
		if opt.MaxScans > 0 && i >= opt.MaxScans {
			if j.prev != nil {
				entries[key] = *j.prev
			}
			continue
		}
		if ctx.Err() != nil {
			if j.prev != nil {
				entries[key] = *j.prev
			}
			continue
		}
		logf("[%d/%d] %s (%s)", i+1, len(jobs), j.img.Ref, j.platform)
		rep, err := scan(ctx, j.img.Ref, j.platform)
		e := Entry{Ref: j.img.Ref, Platform: j.platform, Kind: j.img.Kind, Owner: j.img.Owner, Note: j.img.Note,
			TagDigest: j.digest, CheckedAt: stamp, ScannedAt: stamp}
		if err != nil {
			if msg := describeScanError(err); msg == noBuild {
				// A permanent condition, not a failure: cache it until the tag changes.
				e.Action = noBuildAction
			} else {
				e.Error = msg
			}
			logf("  %s", describeScanError(err))
		} else {
			fill(&e, rep)
			if rep.Data.GrypeDBBuilt != "" {
				next.GrypeDBBuilt = rep.Data.GrypeDBBuilt
			}
		}
		if j.prev != nil {
			e.FirstFixedDigest, e.FirstFixedSeen = j.prev.FirstFixedDigest, j.prev.FirstFixedSeen
			if e.Error == "" && j.prev.Action == string(verdict.ActionNeeded) && e.Action == string(verdict.ActionOK) {
				e.FirstFixedDigest, e.FirstFixedSeen = e.ImageDigest, stamp
			}
			if e.Error != "" && j.prev.Error == "" && j.prev.TagDigest == j.digest {
				// A transient failure shouldn't erase good data for an unchanged tag.
				keep := *j.prev
				keep.CheckedAt = stamp
				keep.Error = ""
				entries[key] = keep
				continue
			}
		}
		if c, ok := diff(j.prev, e, stamp); ok {
			changes = append(changes, c)
		}
		entries[key] = e
	}

	// Labels come from the image list, so edits there apply without a rescan.
	meta := map[string]Image{}
	for _, img := range images {
		meta[img.Ref] = img
	}
	for _, e := range entries {
		if img, ok := meta[e.Ref]; ok {
			e.Kind, e.Owner, e.Note = img.Kind, img.Owner, img.Note
		}
		next.Entries = append(next.Entries, e)
	}
	sort.Slice(next.Entries, func(a, b int) bool {
		if next.Entries[a].Ref != next.Entries[b].Ref {
			return next.Entries[a].Ref < next.Entries[b].Ref
		}
		return next.Entries[a].Platform < next.Entries[b].Platform
	})
	return next, changes
}

func fill(e *Entry, r verdict.Report) {
	e.ImageDigest = r.Image.ManifestDigest
	e.ImageCreated = r.Image.Created
	e.BuiltBeforeFix = r.Image.BuiltBeforeFix
	e.Distro = strings.TrimSpace(r.Distro.ID + " " + r.Distro.Version)
	e.Action = string(r.Action)
	if len(r.Verdicts) > 0 {
		e.Verdicts = map[string]string{}
		for k, v := range r.Verdicts {
			e.Verdicts[k] = string(v)
		}
	}
	for _, p := range r.PHP {
		e.PHP = append(e.PHP, PHP{Name: p.Name, Version: p.Version, Source: p.Source, Provider: p.Provider, SAPI: p.SAPI})
	}
	if s, ok := r.Settings[phpini.UploadProgress]; ok {
		e.UploadProgress = s.Effective
	}
}

func diff(prev *Entry, e Entry, stamp string) (Change, bool) {
	c := Change{Time: stamp, Ref: e.Ref, Platform: e.Platform, ToDigest: e.ImageDigest, ToAction: e.Action, Verdicts: e.Verdicts}
	if prev == nil {
		return c, e.Error == ""
	}
	c.FromDigest, c.FromAction = prev.ImageDigest, prev.Action
	if e.Error != "" {
		return c, false
	}
	if prev.ImageDigest != e.ImageDigest || prev.Action != e.Action || !sameVerdicts(prev.Verdicts, e.Verdicts) {
		return c, true
	}
	return c, false
}

func sameVerdicts(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func describeScanError(err error) string {
	msg := err.Error()
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "no child with platform"), strings.Contains(low, "no matching manifest"),
		strings.Contains(low, "platform") && strings.Contains(low, "not found"):
		return noBuild
	case strings.Contains(low, "toomanyrequests"), strings.Contains(low, "rate limit"):
		return "registry rate limit reached"
	}
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	return msg
}
