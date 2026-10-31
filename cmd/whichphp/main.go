// Command whichphp finds every PHP in a container image and says whether it is fixed
// for PHP2Shell (CVE-2026-109618 / CVE-2026-109619), without running the image.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/yusufyildiz34/whichphp/internal/advisory"
	"github.com/yusufyildiz34/whichphp/internal/grypejson"
	"github.com/yusufyildiz34/whichphp/internal/report"
	"github.com/yusufyildiz34/whichphp/internal/runner"
	"github.com/yusufyildiz34/whichphp/internal/syftjson"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `whichphp: which PHP is inside this image, and is it really fixed for PHP2Shell?

Usage:
  whichphp image [flags] <image>
  whichphp image --sbom <syft.json> [--grype-json <grype.json>] [flags]
  whichphp cluster --context <name> [-n namespace] [-l selector] [flags]
  whichphp index [--images index/images.csv] [--data data] [flags]
  whichphp version

<image> is anything Syft accepts: nginx:latest, registry:repo/app:tag,
docker:app:tag (local Docker), docker-archive:img.tar, oci-archive:img.tar.

whichphp never runs the image. It needs syft and grype on PATH
(or WHICHPHP_SYFT / WHICHPHP_GRYPE).

Output formats (-o, repeatable; add =<file> to write to a file):
  table (default), json, sarif (GitHub code scanning), openvex
  e.g. whichphp image -o table -o sarif=whichphp.sarif php:8.4-apache

Exit codes: 0 fixed or no PHP, 1 action needed, 2 unknown, 3 error.

"whichphp cluster" reads which images a cluster's pods actually run (kubectl get,
nothing else) and says which workloads to redeploy and which images to rebuild.
Run "whichphp cluster -h" for its flags.

Flags for "image":
`

func main() {
	// Builds without -ldflags (go install, or go build in a checkout) report the
	// module version recorded in the build info instead.
	if bi, ok := debug.ReadBuildInfo(); ok && version == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = bi.Main.Version
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		newImageFlags(nil).fs.PrintDefaults()
		return 3
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "whichphp %s\n", version)
		return 0
	case "image":
		return runImage(args[1:], stdout, stderr)
	case "index":
		return runIndex(args[1:], stdout, stderr)
	case "cluster":
		return runCluster(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		newImageFlags(stdout).fs.PrintDefaults()
		return 0
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return 3
}

// output is one -o value: a format, written to stdout or to a file.
type output struct{ format, file string }

// outputList collects repeated -o flags.
type outputList []output

var outputFormats = []string{"table", "json", "sarif", "openvex"}

func (o *outputList) String() string {
	var parts []string
	for _, x := range *o {
		if x.file != "" {
			parts = append(parts, x.format+"="+x.file)
		} else {
			parts = append(parts, x.format)
		}
	}
	return strings.Join(parts, ",")
}

func (o *outputList) Set(v string) error {
	format, file, hasFile := strings.Cut(v, "=")
	if hasFile && strings.TrimSpace(file) == "" {
		return fmt.Errorf("give a file name after %s=, or leave out the = to write to stdout", format)
	}
	ok := false
	for _, f := range outputFormats {
		ok = ok || f == format
	}
	if !ok {
		return fmt.Errorf("unknown output format %q (use %s)", format, strings.Join(outputFormats, ", "))
	}
	*o = append(*o, output{format: format, file: file})
	return nil
}

// toStdout is the output written to stdout, if any.
func (o outputList) toStdout() (output, bool) {
	for _, x := range o {
		if x.file == "" {
			return x, true
		}
	}
	return output{}, false
}

// destination is an output whose file, if any, was opened before the scan, so a bad
// path fails at once instead of after a long scan. A regular file is written to a
// temporary file next to it and renamed into place only when every output is
// complete. Anything else that already exists (a symlink, a pipe, /dev/stdout) is
// written directly.
type destination struct {
	output
	path   string   // absolute path of the final file; "" for stdout
	file   *os.File // where the output is written
	direct bool     // file is the destination itself, not a temporary file
}

// prepareOutputs checks the outputs and opens a temporary file for each file output.
// inputs are files the run reads, which an output must not overwrite.
func prepareOutputs(outs outputList, inputs ...string) ([]destination, error) {
	seen := map[string]bool{}
	for _, in := range inputs {
		if in != "" {
			if abs, err := filepath.Abs(in); err == nil {
				seen[abs] = true
			}
		}
	}
	var dests []destination
	stdoutCount := 0
	for _, o := range outs {
		if o.file == "" {
			if stdoutCount++; stdoutCount > 1 {
				abort(dests)
				return nil, errors.New("only one -o can write to stdout; give the others a file, e.g. -o sarif=whichphp.sarif")
			}
			dests = append(dests, destination{output: o})
			continue
		}
		abs, err := filepath.Abs(o.file)
		if err != nil {
			abort(dests)
			return nil, err
		}
		if seen[abs] {
			abort(dests)
			return nil, fmt.Errorf("%s is used twice: as an input or by another -o", o.file)
		}
		seen[abs] = true
		d := destination{output: o, path: abs}
		if fi, err := os.Lstat(abs); err == nil && !fi.Mode().IsRegular() {
			if fi.IsDir() {
				abort(dests)
				return nil, fmt.Errorf("%s is a directory; give a file name", o.file)
			}
			d.direct = true
			d.file, err = os.OpenFile(abs, os.O_WRONLY|os.O_TRUNC, 0)
			if err != nil {
				abort(dests)
				return nil, fmt.Errorf("can't write %s: %w", o.file, err)
			}
		} else {
			d.file, err = os.CreateTemp(filepath.Dir(abs), "."+filepath.Base(abs)+".*.tmp")
			if err == nil {
				// CreateTemp makes the file private; reports are meant to be read.
				err = d.file.Chmod(0o644)
			}
			if err != nil {
				if d.file != nil {
					d.file.Close()
					os.Remove(d.file.Name())
				}
				abort(dests)
				return nil, fmt.Errorf("can't write %s: %w", o.file, err)
			}
		}
		dests = append(dests, d)
	}
	return dests, nil
}

// abort closes the outputs that weren't completed and removes their temporary files.
func abort(dests []destination) {
	for _, d := range dests {
		if d.file == nil {
			continue
		}
		d.file.Close()
		if !d.direct {
			os.Remove(d.file.Name())
		}
	}
}

type imageFlags struct {
	fs               *flag.FlagSet
	outputs          outputList
	platform         string
	sbom             string
	grypeJSON        string
	noGrype          bool
	maxDBAgeDays     int
	failOnMitigation bool
	skipFeedCheck    bool
	keep             string
	verbose          bool
	vexAuthor        string
	// quiet silences progress messages (whichphp index sets it).
	quiet bool
}

func newImageFlags(out io.Writer) *imageFlags {
	f := &imageFlags{fs: flag.NewFlagSet("image", flag.ContinueOnError)}
	if out != nil {
		f.fs.SetOutput(out)
	}
	f.fs.Var(&f.outputs, "o", "output to write, as `format[=file]`: table, json, sarif or openvex; repeatable (default table)")
	f.fs.StringVar(&f.platform, "platform", "", "image platform, e.g. linux/arm64")
	f.fs.StringVar(&f.sbom, "sbom", "", "use an existing Syft JSON SBOM instead of scanning")
	f.fs.StringVar(&f.grypeJSON, "grype-json", "", "use existing Grype JSON output instead of running grype")
	f.fs.BoolVar(&f.noGrype, "no-grype", false, "don't use Grype; distro packages get UNKNOWN")
	f.fs.IntVar(&f.maxDBAgeDays, "max-db-age", 7, "days after which Grype's database counts as stale (0 to disable)")
	f.fs.BoolVar(&f.failOnMitigation, "fail-on-mitigation", false, "exit 1 when session.upload_progress is on (CVE-2026-115560)")
	f.fs.BoolVar(&f.skipFeedCheck, "skip-feed-check", false, "don't ask Grype's database whether distro feeds list the CVEs")
	f.fs.StringVar(&f.keep, "keep", "", "directory to keep the SBOM and Grype output in")
	f.fs.BoolVar(&f.verbose, "verbose", false, "show Syft and Grype progress")
	f.fs.StringVar(&f.vexAuthor, "vex-author", "", "author named in OpenVEX output (default \"whichphp automated scan\")")
	return f
}

// parseInterspersed allows flags before and after the positional argument.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func runImage(args []string, stdout, stderr io.Writer) int {
	f := newImageFlags(stderr)
	pos, err := parseInterspersed(f.fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 3
	}
	if len(f.outputs) == 0 {
		f.outputs = outputList{{format: "table"}}
	}
	if len(pos) > 1 || (len(pos) == 0 && f.sbom == "") {
		fmt.Fprintln(stderr, "give exactly one image, or --sbom <file>")
		return 3
	}
	input := ""
	if len(pos) == 1 {
		input = pos[0]
	}
	if strings.HasPrefix(input, "-") {
		fmt.Fprintf(stderr, "whichphp: %q isn't an image reference\n", input)
		return 3
	}

	dests, err := prepareOutputs(f.outputs, f.sbom, f.grypeJSON)
	if err != nil {
		fmt.Fprintf(stderr, "whichphp: %v\n", err)
		return 3
	}
	defer abort(dests)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	rep, err := scan(ctx, f, input, stderr, nil)
	if err != nil {
		// The error can quote the image or the tools' output: one clean line, so it
		// can't start a CI log command.
		fmt.Fprintf(stderr, "whichphp: %s\n", report.Clean(err.Error()))
		return 3
	}
	// Write every file, then move them all into place, then print to stdout: a run
	// that fails on one output leaves none of its files behind.
	vex := report.VEXOptions{Author: f.vexAuthor}
	for i := range dests {
		d := &dests[i]
		if d.file == nil {
			continue
		}
		err := writeOutput(d.file, d.format, rep, vex)
		if cerr := d.file.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			fmt.Fprintf(stderr, "whichphp: writing %s: %v\n", d.output.file, err)
			return 3
		}
		if d.direct {
			d.file = nil
		}
	}
	for i := range dests {
		d := &dests[i]
		if d.file == nil {
			continue
		}
		if err := os.Rename(d.file.Name(), d.path); err != nil {
			fmt.Fprintf(stderr, "whichphp: writing %s: %v\n", d.output.file, err)
			return 3
		}
		d.file = nil
	}
	for _, d := range dests {
		if d.path == "" {
			if err := writeOutput(stdout, d.format, rep, vex); err != nil {
				fmt.Fprintf(stderr, "whichphp: %v\n", err)
				return 3
			}
		}
	}
	return rep.Action.ExitCode()
}

func writeOutput(w io.Writer, format string, rep verdict.Report, vex report.VEXOptions) error {
	switch format {
	case "table":
		return report.Table(w, rep)
	case "json":
		return report.JSON(w, rep)
	case "sarif":
		return report.SARIF(w, rep)
	case "openvex":
		return report.OpenVEX(w, rep, vex)
	}
	return fmt.Errorf("unknown output format %q", format)
}

// feedCache remembers feed-coverage answers per distro release within one run.
type feedCache map[string]map[string]grypejson.FeedStatus

func scan(ctx context.Context, f *imageFlags, input string, stderr io.Writer, cache feedCache) (verdict.Report, error) {
	useGrype := !f.noGrype
	needSyft := f.sbom == ""
	needGrypeBin := useGrype && (f.grypeJSON == "" || !f.skipFeedCheck)

	var tools runner.Tools
	if needSyft || needGrypeBin {
		t, err := runner.Find(needGrypeBin)
		if err != nil && (needSyft || f.grypeJSON == "") {
			return verdict.Report{}, err
		}
		tools = t
		tools.Verbose = f.verbose
	}

	dir := f.keep
	if dir == "" {
		tmp, err := os.MkdirTemp("", "whichphp-")
		if err != nil {
			return verdict.Report{}, err
		}
		defer os.RemoveAll(tmp)
		dir = tmp
	} else if err := os.MkdirAll(dir, 0o755); err != nil {
		return verdict.Report{}, err
	}

	// 1. SBOM.
	sbomPath := f.sbom
	captured := false
	if sbomPath == "" {
		progress(stderr, f, "Cataloging %s with Syft (the image is read, never run)...", input)
		p, err := tools.SBOM(ctx, input, f.platform, dir)
		if err != nil {
			return verdict.Report{}, err
		}
		sbomPath, captured = p, true
	}
	doc, err := syftjson.Load(sbomPath)
	if err != nil {
		return verdict.Report{}, err
	}

	in := verdict.Inputs{
		Doc: doc, Input: input, ContentCaptured: captured, Now: time.Now(),
		MaxDBAge: time.Duration(f.maxDBAgeDays) * 24 * time.Hour, FailOnMitigation: f.failOnMitigation,
		ToolVersion: version,
	}

	// 2. Vulnerability matches.
	if useGrype {
		grypePath := f.grypeJSON
		if grypePath == "" {
			progress(stderr, f, "Matching with Grype...")
			p, err := tools.Match(ctx, sbomPath, dir)
			if err != nil {
				return verdict.Report{}, err
			}
			grypePath = p
		}
		hits, err := grypejson.LoadMatches(grypePath, advisory.CVEs)
		if err != nil {
			return verdict.Report{}, err
		}
		in.GrypeRan, in.Hits = true, hits

		if tools.Grype != "" {
			if b, err := tools.DBStatus(ctx); err == nil {
				if s, err := grypejson.ParseStatus(b); err == nil && !s.Built.IsZero() {
					in.DBBuilt = s.Built
				}
			}
			if !f.skipFeedCheck && hasDistroPHP(doc) {
				key := grypeDistro(doc.Distro.ID, doc.Distro.VersionID)
				if cached, ok := cache[key]; ok && key != "" {
					in.Feed = cached
				} else {
					in.Feed = feedCoverage(ctx, tools, stderr, f, doc, dir)
					if cache != nil && key != "" {
						cache[key] = in.Feed
					}
				}
			}
		}
	}

	return verdict.Evaluate(in), nil
}

// feedCoverage asks Grype's database whether the image's distro security data lists
// each CVE. Grype filters by distro itself (--distro), so release naming differences
// don't matter: Grype's output writes Ubuntu 24.04 as "24.4" and RHEL as "redhat",
// while Syft reports "24.04" and "rhel". Comparing those ourselves gave false
// NEEDS_VENDOR_CONFIRMATION verdicts. It returns nil when the answer can't be trusted, and verdicts then fall
// back to match-only evidence. The raw outputs are saved in dir.
func feedCoverage(ctx context.Context, tools runner.Tools, stderr io.Writer, f *imageFlags, doc *syftjson.Document, dir string) map[string]grypejson.FeedStatus {
	distro := grypeDistro(doc.Distro.ID, doc.Distro.VersionID)
	if distro == "" {
		return nil
	}
	out := map[string]grypejson.FeedStatus{}
	for _, cve := range advisory.CVEs {
		// First make sure the database knows the CVE at all and that we can read the output.
		all, err := tools.DBSearch(ctx, cve, "")
		saveRaw(dir, "dbsearch-"+cve+".json", all)
		if err != nil {
			progress(stderr, f, "Couldn't search Grype's database (%v); distro verdicts use matches only.", err)
			return nil
		}
		if entries, err := grypejson.ParseSearch(all); err != nil || len(entries) == 0 {
			progress(stderr, f, "Couldn't read Grype's database search output; distro verdicts use matches only.")
			return nil
		}
		filtered, err := tools.DBSearch(ctx, cve, distro)
		saveRaw(dir, "dbsearch-"+cve+"-"+strings.ReplaceAll(distro, ":", "-")+".json", filtered)
		if err != nil {
			progress(stderr, f, "Couldn't search Grype's database for %s (%v); distro verdicts use matches only.", distro, err)
			return nil
		}
		entries, err := grypejson.ParseSearch(filtered)
		if err != nil {
			return nil
		}
		st := grypejson.FeedStatus{}
		for _, e := range entries {
			if e.Package != "" && !strings.Contains(strings.ToLower(e.Package), "php") {
				continue
			}
			st.Listed = true
			if st.FixVersion == "" {
				st.FixVersion, st.Package = e.FixVersion, e.Package
			}
		}
		out[cve] = st
	}
	return out
}

// grypeDistro formats a distro for `grype db search --distro`, e.g. "ubuntu:24.04",
// "debian:13", "alpine:3.24".
func grypeDistro(id, version string) string {
	if id == "" || version == "" {
		return ""
	}
	return id + ":" + advisory.NormalizeRelease(id, version)
}

func saveRaw(dir, name string, b []byte) {
	if dir == "" || len(b) == 0 {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, name), b, 0o644)
}

func hasDistroPHP(doc *syftjson.Document) bool {
	for _, p := range verdict.Find(doc) {
		if p.Source == verdict.SourceDistro {
			return true
		}
	}
	return false
}

func progress(w io.Writer, f *imageFlags, format string, a ...any) {
	if f.quiet && !f.verbose {
		return
	}
	if o, ok := f.outputs.toStdout(); ok && o.format != "table" && !f.verbose {
		return
	}
	// The input can come from a pod spec; keep it from starting a CI log command.
	fmt.Fprintln(w, report.Clean(fmt.Sprintf(format, a...)))
}
