package cluster

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/yusufyildiz34/whichphp/internal/report"
)

var actionTitles = map[string]string{
	ActionNeeded:  "ACTION NEEDED",
	ActionUnknown: "UNKNOWN",
	ActionError:   "NOT CHECKED",
	ActionOK:      "OK",
	ActionNoPHP:   "NO PHP",
}

var verdictLabels = map[string]string{
	"VULNERABLE_EOL":            "end-of-life PHP",
	"VULNERABLE":                "vulnerable",
	"DATA_STALE":                "data out of date",
	"UNKNOWN":                   "unknown",
	"NEEDS_VENDOR_CONFIRMATION": "ask the vendor",
	"FIXED_BY_DISTRO_BACKPORT":  "fixed by distro backport",
	"FIXED":                     "fixed",
	"NOT_AFFECTED":              "not affected",
}

// The reminders every report ends with.
var (
	evidenceNote = "Before you redeploy: recreating a pod deletes its logs and writable layer. If you need to check whether it was compromised, save them first."
	settingsNote = "Settings come from the images; a php.ini mounted from a ConfigMap or set through the environment isn't read."
)

// errWriter remembers the first write error, so a report can be written with many
// Fprintf calls and checked once.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.w.Write(p)
	if err != nil {
		e.err = err
	}
	return n, err
}

// Table writes a human-readable report, worst workloads first. Workloads without
// PHP are summarized in one line.
func Table(out io.Writer, r Result) error {
	w := &errWriter{w: out}
	c := report.Clean
	fmt.Fprintf(w, "Context: %s\n", c(r.Context))
	fmt.Fprintf(w, "Checked %d running %s: %d %s in %d %s.\n", r.Pods, plural(r.Pods, "pod", "pods"),
		r.Images, plural(r.Images, "image", "images"), len(r.Workloads), plural(len(r.Workloads), "workload", "workloads"))

	var noPHP []string
	for _, wl := range r.Workloads {
		name := c(wl.Namespace + "/" + wl.Kind + "/" + wl.Name)
		if wl.Action == ActionNoPHP {
			noPHP = append(noPHP, name)
			continue
		}
		fmt.Fprintf(w, "\n%-14s %s\n", actionTitles[wl.Action], name)
		for _, cr := range wl.Containers {
			// An OK workload shows only containers with something to say.
			if cr.Result.Action == ActionNoPHP && len(cr.Notes) == 0 || wl.Action == ActionOK && len(cr.Notes) == 0 {
				continue
			}
			kind := ""
			if cr.Init {
				kind = " (init)"
			}
			fmt.Fprintf(w, "  %s%s: %s", c(cr.Name), kind, c(cr.Image))
			if cr.Platform != "" {
				fmt.Fprintf(w, " on %s", c(cr.Platform))
			}
			fmt.Fprintf(w, ", %d %s\n", len(cr.Pods), plural(len(cr.Pods), "pod", "pods"))
			switch {
			case cr.Running != "":
				fmt.Fprintf(w, "    running %s\n", c(shortDigest(Digest(cr.Running))))
			case cr.RunningUnverified && cr.LocalID != "" && cr.Result.ImageID != "":
				fmt.Fprintf(w, "    running image ID %s, not the tag's image now; checked the tag as it is now\n", c(shortDigest(cr.LocalID)))
			case cr.RunningUnverified && cr.LocalID != "":
				fmt.Fprintf(w, "    running image ID %s, which couldn't be compared with the tag's image; checked the tag as it is now\n", c(shortDigest(cr.LocalID)))
			case cr.RunningUnverified:
				fmt.Fprintf(w, "    running an image the runtime didn't name; checked the tag as it is now\n")
			case cr.LocalID != "":
				fmt.Fprintf(w, "    running image ID %s\n", c(shortDigest(cr.LocalID)))
			}
			if line := phpLine(cr.Result); line != "" {
				fmt.Fprintf(w, "    %s\n", line)
			}
			if cr.TagMoved && cr.TagResult != nil {
				fmt.Fprintf(w, "    the tag now points to %s: %s\n", c(shortDigest(cr.TagDigest)), c(statusText(*cr.TagResult)))
			}
			if cr.Advice != "" {
				fmt.Fprintf(w, "    %s\n", c(cr.Advice))
			}
			for _, n := range cr.Notes {
				fmt.Fprintf(w, "    Note: %s\n", c(n))
			}
		}
		if wl.Restart != "" {
			fmt.Fprintf(w, "  Redeploy: %s\n", c(wl.Restart))
		}
	}
	if len(noPHP) > 0 {
		sort.Strings(noPHP)
		fmt.Fprintf(w, "\nNo PHP in %d %s: %s\n", len(noPHP), plural(len(noPHP), "workload", "workloads"), strings.Join(noPHP, ", "))
	}
	fmt.Fprintln(w)
	for _, n := range r.Notes {
		fmt.Fprintf(w, "Note: %s\n", c(n))
	}
	if r.Action == ActionNeeded {
		fmt.Fprintln(w, evidenceNote)
	}
	fmt.Fprintln(w, settingsNote)
	return w.err
}

// JSON writes the full report.
func JSON(out io.Writer, r Result) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

func phpLine(r ImageResult) string {
	if len(r.PHP) == 0 {
		return ""
	}
	seen := map[string]bool{}
	var vs []string
	for _, p := range r.PHP {
		v := report.Clean(p.Version)
		if !seen[v] {
			seen[v] = true
			vs = append(vs, v)
		}
	}
	return "PHP " + strings.Join(vs, ", ") + ": " + statusText(r)
}

// statusText names the worst verdict across the CVEs, or the action.
func statusText(r ImageResult) string {
	if r.Error != "" {
		return "couldn't be checked"
	}
	worst, w := "", -1
	order := []string{"FIXED", "NOT_AFFECTED", "FIXED_BY_DISTRO_BACKPORT", "NEEDS_VENDOR_CONFIRMATION", "UNKNOWN", "DATA_STALE", "VULNERABLE", "VULNERABLE_EOL"}
	for _, v := range r.Verdicts {
		i := -1
		for j, o := range order {
			if o == v {
				i = j
			}
		}
		if i < 0 {
			i = 4 // an unrecognized verdict counts as unknown
		}
		if i > w {
			worst, w = v, i
		}
	}
	if l, ok := verdictLabels[worst]; ok {
		return l
	}
	switch r.Action {
	case ActionNoPHP:
		return "no PHP"
	case ActionOK:
		return "fixed"
	}
	return "unknown"
}

func shortDigest(d string) string {
	if strings.HasPrefix(d, "sha256:") && len(d) > 19 {
		return d[:19] + "…"
	}
	return d
}
