// Package report renders a verdict report as a table, JSON, SARIF or OpenVEX.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/yusufyildiz34/whichphp/internal/advisory"
	"github.com/yusufyildiz34/whichphp/internal/phpini"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

// JSON writes the report as indented JSON.
func JSON(w io.Writer, r verdict.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// errWriter remembers the first write error, so Table can report it once.
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

// clean makes text that comes from the image safe to print in a CI log, which reads
// workflow commands from it. Control characters, including newlines, become "?", so a
// crafted package name can't start a new line. A "::" after any leading white space
// becomes "?:", because the GitHub Actions runner trims a line before it looks for
// "::command". And "##[" becomes "#?[" wherever it is, because the runner also reads
// the older "##[command]" form anywhere in a line.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return '?'
		}
		return r
	}, s)
	if t := strings.TrimLeftFunc(s, unicode.IsSpace); strings.HasPrefix(t, "::") {
		i := len(s) - len(t)
		s = s[:i] + "?" + s[i+1:]
	}
	return strings.ReplaceAll(s, "##[", "#?[")
}

// Clean is clean for other packages that print text from images or clusters.
func Clean(s string) string { return clean(s) }

// Table writes a human-readable report.
func Table(out io.Writer, r verdict.Report) error {
	w := &errWriter{w: out}
	fmt.Fprintf(w, "Image:   %s\n", clean(imageLabel(r)))
	if r.Image.ManifestDigest != "" {
		fmt.Fprintf(w, "Digest:  %s", clean(r.Image.ManifestDigest))
		if r.Image.Architecture != "" {
			fmt.Fprintf(w, " (%s)", clean(r.Image.Architecture))
		}
		fmt.Fprintln(w)
	}
	if r.Distro.ID != "" {
		fmt.Fprintf(w, "Distro:  %s %s (%s)\n", clean(r.Distro.ID), clean(r.Distro.Version), r.Distro.Support)
	}
	if r.Image.Created != "" {
		built := ""
		if r.Image.BuiltBeforeFix != nil && *r.Image.BuiltBeforeFix {
			built = ", before the Oct 21, 2026 fixes"
		}
		fmt.Fprintf(w, "Created: %s%s\n", clean(r.Image.Created), built)
	}
	if r.Image.ServingHint != "" {
		fmt.Fprintf(w, "Serves:  %s\n", clean(r.Image.ServingHint))
	}
	fmt.Fprintln(w)

	if len(r.PHP) == 0 {
		fmt.Fprintln(w, "No PHP found in this image.")
		return w.err
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PHP\tVERSION\tSOURCE\tSAPI\t"+strings.Join(shortCVEs(), "\t"))
	for _, p := range r.PHP {
		src := p.Source
		if p.Provider != "" {
			src += " (" + p.Provider + ")"
		}
		cells := []string{p.Name, p.Version, src, p.SAPI}
		for i := range cells {
			cells[i] = strings.ReplaceAll(clean(cells[i]), "\t", " ")
		}
		for _, c := range advisory.CVEs {
			cells = append(cells, string(p.CVEs[c].Verdict))
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	tw.Flush()

	fmt.Fprintln(w, "\nWhy:")
	for _, p := range r.PHP {
		reasons := map[string][]string{}
		for _, c := range advisory.CVEs {
			why := p.CVEs[c].Why
			reasons[why] = append(reasons[why], c)
		}
		keys := make([]string, 0, len(reasons))
		for k := range reasons {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, why := range keys {
			fmt.Fprintf(w, "  %s %s (%s): %s\n", clean(p.Name), clean(p.Version), strings.Join(reasons[why], ", "), clean(why))
		}
		if len(p.Paths) > 0 {
			shown, more := p.Paths, ""
			if len(shown) > 2 {
				shown, more = shown[:2], fmt.Sprintf(" (+%d more)", len(p.Paths)-2)
			}
			fmt.Fprintf(w, "    evidence: %s%s\n", clean(strings.Join(shown, ", ")), more)
		}
	}

	if len(r.Settings) > 0 {
		fmt.Fprintln(w, "\nSettings (image defaults; runtime config can override):")
		names := make([]string, 0, len(r.Settings))
		for n := range r.Settings {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			s := r.Settings[n]
			fmt.Fprintf(w, "  %s = %s: %s\n", n, s.Effective, clean(s.Why))
			if n == phpini.UploadProgress && (s.Effective == "on" || s.Effective == "unknown") {
				fmt.Fprintf(w, "    %s has no fix yet; turning this off server-wide is the mitigation.\n", advisory.MitigationCVE)
			}
		}
	}

	if len(r.Notes) > 0 {
		fmt.Fprintln(w, "\nNotes:")
		for _, n := range r.Notes {
			fmt.Fprintf(w, "  - %s\n", clean(n))
		}
	}

	fmt.Fprintf(w, "\nResult: %s\n", describe(r.Action))
	fmt.Fprintln(w, "A verdict covers the PHP in this image only. It says nothing about earlier compromise.")
	return w.err
}

func shortCVEs() []string {
	out := make([]string, len(advisory.CVEs))
	for i, c := range advisory.CVEs {
		out[i] = strings.TrimPrefix(c, "CVE-")
	}
	return out
}

func describe(a verdict.Action) string {
	switch a {
	case verdict.ActionOK:
		return "OK: every PHP in this image is fixed for both CVEs (exit 0)"
	case verdict.ActionNeeded:
		return "ACTION NEEDED: rebuild or replace this image (exit 1)"
	case verdict.ActionUnknown:
		return "UNKNOWN: not enough evidence either way; see the reasons above (exit 2)"
	case verdict.ActionNoPHP:
		return "no PHP found (exit 0)"
	}
	return string(a)
}
