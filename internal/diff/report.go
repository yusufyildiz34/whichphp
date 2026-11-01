package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/yusufyildiz34/whichphp/internal/phpini"
	"github.com/yusufyildiz34/whichphp/internal/report"
)

var actionTitles = map[string]string{
	"OK":            "OK",
	"ACTION_NEEDED": "ACTION NEEDED",
	"UNKNOWN":       "UNKNOWN",
	"NO_PHP":        "NO PHP",
}

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

// Table writes the comparison for people: the two images side by side, each PHP build
// and what happened to it, and the result.
func Table(out io.Writer, d Diff) error {
	w := &errWriter{w: out}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	row := func(label, before, after string) {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", cell(label), cell(before), cell(after))
	}
	fmt.Fprintln(tw, "\tBEFORE\tAFTER")
	row("Image", d.Before.Name, d.After.Name)
	for _, r := range []struct{ label, before, after string }{
		{"Digest", shortDigest(d.Before.Digest), shortDigest(d.After.Digest)},
		{"Architecture", d.Before.Architecture, d.After.Architecture},
		{"Created", d.Before.Created, d.After.Created},
		{"Distro", d.Before.Distro, d.After.Distro},
	} {
		if r.before != "" || r.after != "" {
			row(r.label, r.before, r.after)
		}
	}
	for _, cve := range cveOrder(d.Verdicts) {
		c := d.Verdicts[cve]
		row(cve, verdictText(c, false), verdictText(c, true))
	}
	if d.UploadProgress != (Change{}) {
		row(phpini.UploadProgress, d.UploadProgress.Before, d.UploadProgress.After)
	}
	row("Action", actionTitle(d.Action.Before), actionTitle(d.Action.After))
	tw.Flush()

	fmt.Fprintln(w)
	if len(d.PHP) == 0 {
		fmt.Fprintln(w, "No PHP found in either image.")
	} else {
		fmt.Fprintln(w, "PHP builds:")
		for _, b := range d.PHP {
			line(w, "  %-9s  %s", b.Change, buildText(b))
			for _, l := range cveLines(b) {
				line(w, "    %s", l)
			}
		}
	}

	if len(d.Notes) > 0 {
		fmt.Fprintln(w, "\nNotes:")
		for _, n := range d.Notes {
			line(w, "  - %s", n)
		}
	}
	if len(d.After.Notes) > 0 {
		fmt.Fprintln(w, "\nNotes on the after image:")
		for _, n := range d.After.Notes {
			line(w, "  - %s", n)
		}
	}

	fmt.Fprintln(w)
	line(w, "Result: %s: %s (exit %d)", d.Summary, transition(d.Action), d.ExitCode())
	fmt.Fprintln(w, "A verdict covers the PHP in these images only. It says nothing about earlier compromise.")
	return w.err
}

// JSON writes the comparison as indented JSON.
func JSON(out io.Writer, d Diff) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(d)
}

// line writes one line whose text can come from the reports. It is cleaned as a whole,
// so no two values can join into a workflow command.
func line(w io.Writer, format string, a ...any) {
	fmt.Fprintln(w, report.Clean(fmt.Sprintf(format, a...)))
}

// cell makes a value from a report safe for a table cell; "-" stands for no value.
func cell(s string) string {
	if s == "" {
		return "-"
	}
	return report.Clean(s)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// buildText names a build and its change: "libphp 8.4.26 → 8.4.27 (apache-module)".
func buildText(b Build) string {
	nameVersion := func(p *PHP) string { return strings.TrimSpace(p.Name + " " + p.Version) }
	var text, sapi string
	switch {
	case b.Before != nil && b.After != nil:
		sapi = b.After.SAPI
		switch {
		case b.Change == Unchanged:
			text = nameVersion(b.After)
		case b.Before.Name == b.After.Name:
			text = fmt.Sprintf("%s %s → %s", b.After.Name, orDash(b.Before.Version), orDash(b.After.Version))
		default:
			text = nameVersion(b.Before) + " → " + nameVersion(b.After)
		}
	case b.After != nil:
		text, sapi = nameVersion(b.After), b.After.SAPI
	case b.Before != nil:
		text, sapi = nameVersion(b.Before), b.Before.SAPI
	}
	if b.Match == MatchSAPI {
		return fmt.Sprintf("%s (%s, matched by SAPI)", text, orDash(sapi))
	}
	return fmt.Sprintf("%s (%s)", text, orDash(sapi))
}

// verdictText is one side of a verdict change, with an unconfirmed distro backport
// marked: "FIXED_BY_DISTRO_BACKPORT (unconfirmed)".
func verdictText(c VerdictChange, after bool) string {
	v, marked := c.Before, c.Unconfirmed != nil && c.Unconfirmed.Before
	if after {
		v, marked = c.After, c.Unconfirmed != nil && c.Unconfirmed.After
	}
	if marked && v != "" {
		return v + " (unconfirmed)"
	}
	return v
}

// cveLines says what happened to a build's verdict per CVE, one line per distinct
// change: "CVE-2026-109618, CVE-2026-109619: VULNERABLE → FIXED".
func cveLines(b Build) []string {
	var texts []string
	byText := map[string][]string{}
	for _, cve := range cveOrder(b.CVEs) {
		c := b.CVEs[cve]
		before, after := orDash(verdictText(c, false)), orDash(verdictText(c, true))
		var t string
		switch {
		case b.Change == Added:
			t = after
		case b.Change == Removed:
			t = before
		case before == after:
			t = after
		default:
			t = before + " → " + after
		}
		if _, ok := byText[t]; !ok {
			texts = append(texts, t)
		}
		byText[t] = append(byText[t], cve)
	}
	out := make([]string, len(texts))
	for i, t := range texts {
		out[i] = strings.Join(byText[t], ", ") + ": " + t
	}
	return out
}

func actionTitle(a string) string {
	if t, ok := actionTitles[a]; ok {
		return t
	}
	return a
}

// transition says how the action changed: "ACTION NEEDED → OK".
func transition(c Change) string {
	before, after := orDash(actionTitle(c.Before)), orDash(actionTitle(c.After))
	if before == after {
		return before + " before and after"
	}
	return before + " → " + after
}

func shortDigest(d string) string {
	if strings.HasPrefix(d, "sha256:") && len(d) > 19 {
		return d[:19] + "…"
	}
	return d
}
