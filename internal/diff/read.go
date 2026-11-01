package diff

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/yusufyildiz34/whichphp/internal/advisory"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

// maxReportSize bounds a report file. whichphp's own reports take a few kilobytes.
const maxReportSize = 4 << 20

var utf8BOM = []byte("\xef\xbb\xbf")

// ReadReport reads the report in a file named on the command line. ok is false when path
// isn't an existing regular file, or is a file that doesn't start like JSON (an image
// archive, say): the caller then scans it as an image. A file that starts like JSON but
// isn't a whichphp image report is an error, and so is any name ending in .json that
// isn't a report, so a mistyped report is never scanned as an image.
func ReadReport(path string) (r verdict.Report, ok bool, err error) {
	jsonName := strings.EqualFold(filepath.Ext(path), ".json")
	fi, err := os.Stat(path)
	if err == nil && !fi.Mode().IsRegular() {
		err = fmt.Errorf("%s isn't a regular file", path)
	}
	if err != nil {
		if jsonName {
			return verdict.Report{}, false, fmt.Errorf("can't read the report: %w", err)
		}
		return verdict.Report{}, false, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return verdict.Report{}, false, err
	}
	defer f.Close()
	head := make([]byte, 512)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return verdict.Report{}, false, err
	}
	if !jsonName && !startsLikeJSON(head[:n]) {
		return verdict.Report{}, false, nil
	}
	if fi.Size() > maxReportSize {
		return verdict.Report{}, false, fmt.Errorf("%s is too large to be a whichphp report", path)
	}
	rest, err := io.ReadAll(io.LimitReader(f, maxReportSize))
	if err != nil {
		return verdict.Report{}, false, err
	}
	r, err = ParseReport(append(head[:n], rest...))
	if err != nil {
		return verdict.Report{}, false, fmt.Errorf("%s isn't a whichphp image report (%w); write one with whichphp image -o json=<file>", path, err)
	}
	return r, true, nil
}

// startsLikeJSON reports whether b starts with a JSON object or array, after an
// optional byte order mark and white space.
func startsLikeJSON(b []byte) bool {
	b = bytes.TrimLeft(bytes.TrimPrefix(b, utf8BOM), " \t\r\n")
	return len(b) > 0 && (b[0] == '{' || b[0] == '[')
}

// ParseReport decodes a whichphp image report, as "whichphp image -o json" writes it.
// The report is untrusted input. Anything without a report's shape is an error, so a
// cluster report, the index or an SBOM can't be compared by mistake, and so is a report
// whose action contradicts its verdicts or builds.
func ParseReport(b []byte) (verdict.Report, error) {
	b = bytes.TrimPrefix(b, utf8BOM)
	if t := bytes.TrimLeft(b, " \t\r\n"); len(t) == 0 || t[0] != '{' {
		return verdict.Report{}, errors.New("not a JSON object")
	}
	// Check the shape first, and count the builds before decoding them.
	var shape struct {
		Tool   string            `json:"tool"`
		Image  json.RawMessage   `json:"image"`
		PHP    []json.RawMessage `json:"php"`
		Action verdict.Action    `json:"action"`
	}
	if err := json.Unmarshal(b, &shape); err != nil {
		return verdict.Report{}, err
	}
	switch {
	case shape.Tool != "whichphp":
		return verdict.Report{}, errors.New(`no "tool": "whichphp"`)
	case !bytes.HasPrefix(bytes.TrimLeft(shape.Image, " \t\r\n"), []byte("{")):
		return verdict.Report{}, errors.New(`no "image" object; only reports of "whichphp image" can be compared`)
	case !knownAction(shape.Action):
		return verdict.Report{}, fmt.Errorf("unknown action %q", shape.Action)
	case len(shape.PHP) > maxBuilds:
		return verdict.Report{}, fmt.Errorf("%d PHP builds, more than the %d whichphp compares", len(shape.PHP), maxBuilds)
	}
	var r verdict.Report
	if err := json.Unmarshal(b, &r); err != nil {
		return verdict.Report{}, err
	}
	if err := consistent(r); err != nil {
		return verdict.Report{}, err
	}
	return r, nil
}

// consistent checks that a report's action agrees with what it found, since the action
// sets the exit code and the result of a comparison, as verdict.Evaluate sets it:
//
//   - OK: PHP was found, and every verdict, of the image and of each build, is a fix or
//     not affected, for every CVE whichphp checks;
//   - UNKNOWN: PHP was found, and no verdict is vulnerable;
//   - ACTION_NEEDED: PHP was found (its verdicts may all be fixed, when upload progress
//     on counts as action needed);
//   - NO_PHP: no PHP was found, and no verdict is vulnerable.
//
// A report from another version may carry verdicts this one doesn't know; under OK
// they are refused rather than taken for fixes.
func consistent(r verdict.Report) error {
	vulnerable := false
	var unproven *verdict.Verdict // the first verdict that isn't a fix
	check := func(v verdict.Verdict) {
		vulnerable = vulnerable || v.IsVulnerable()
		if !provenFixed(v) && unproven == nil {
			unproven = &v
		}
	}
	for _, v := range r.Verdicts {
		check(v)
	}
	for _, p := range r.PHP {
		for _, res := range p.CVEs {
			check(res.Verdict)
		}
	}
	switch r.Action {
	case verdict.ActionOK:
		switch {
		case vulnerable:
			return errors.New("the action OK contradicts its vulnerable verdicts")
		case len(r.PHP) == 0:
			return errors.New("the action OK contradicts its lack of PHP builds")
		case unproven != nil:
			return fmt.Errorf("the action OK contradicts its verdict %q, which isn't a fix", *unproven)
		}
		for _, cve := range advisory.CVEs {
			if _, ok := r.Verdicts[cve]; !ok {
				return fmt.Errorf("the action OK contradicts its lack of a verdict for %s", cve)
			}
			for _, p := range r.PHP {
				if _, ok := p.CVEs[cve]; !ok {
					return fmt.Errorf("the action OK contradicts its lack of a verdict for %s on PHP build %q", cve, p.Name)
				}
			}
		}
	case verdict.ActionUnknown, verdict.ActionNeeded:
		switch {
		case len(r.PHP) == 0:
			return fmt.Errorf("the action %s contradicts its lack of PHP builds", r.Action)
		case r.Action == verdict.ActionUnknown && vulnerable:
			return errors.New("the action UNKNOWN contradicts its vulnerable verdicts")
		}
	case verdict.ActionNoPHP:
		switch {
		case vulnerable:
			return errors.New("the action NO_PHP contradicts its vulnerable verdicts")
		case len(r.PHP) > 0:
			return fmt.Errorf("the action NO_PHP contradicts its %d PHP builds", len(r.PHP))
		}
	}
	return nil
}

// provenFixed reports whether a verdict is a fix or not affected.
func provenFixed(v verdict.Verdict) bool {
	switch v {
	case verdict.Fixed, verdict.FixedByDistroBackport, verdict.FixedByVendorBackport, verdict.NotAffected:
		return true
	}
	return false
}

func knownAction(a verdict.Action) bool {
	switch a {
	case verdict.ActionOK, verdict.ActionNeeded, verdict.ActionUnknown, verdict.ActionNoPHP:
		return true
	}
	return false
}
