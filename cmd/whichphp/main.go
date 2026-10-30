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
  whichphp index [--images index/images.csv] [--data data] [flags]
  whichphp version

<image> is anything Syft accepts: nginx:latest, registry:repo/app:tag,
docker:app:tag (local Docker), docker-archive:img.tar, oci-archive:img.tar.

whichphp never runs the image. It needs syft and grype on PATH
(or WHICHPHP_SYFT / WHICHPHP_GRYPE).

Exit codes: 0 fixed or no PHP, 1 action needed, 2 unknown, 3 error.

Flags for "image":
`

func main() {
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
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		newImageFlags(stdout).fs.PrintDefaults()
		return 0
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return 3
}

type imageFlags struct {
	fs               *flag.FlagSet
	output           string
	platform         string
	sbom             string
	grypeJSON        string
	noGrype          bool
	maxDBAgeDays     int
	failOnMitigation bool
	skipFeedCheck    bool
	keep             string
	verbose          bool
}

func newImageFlags(out io.Writer) *imageFlags {
	f := &imageFlags{fs: flag.NewFlagSet("image", flag.ContinueOnError)}
	if out != nil {
		f.fs.SetOutput(out)
	}
	f.fs.StringVar(&f.output, "o", "table", "output format: table or json")
	f.fs.StringVar(&f.platform, "platform", "", "image platform, e.g. linux/arm64")
	f.fs.StringVar(&f.sbom, "sbom", "", "use an existing Syft JSON SBOM instead of scanning")
	f.fs.StringVar(&f.grypeJSON, "grype-json", "", "use existing Grype JSON output instead of running grype")
	f.fs.BoolVar(&f.noGrype, "no-grype", false, "don't use Grype; distro packages get UNKNOWN")
	f.fs.IntVar(&f.maxDBAgeDays, "max-db-age", 7, "days after which Grype's database counts as stale (0 to disable)")
	f.fs.BoolVar(&f.failOnMitigation, "fail-on-mitigation", false, "exit 1 when session.upload_progress is on (CVE-2026-115560)")
	f.fs.BoolVar(&f.skipFeedCheck, "skip-feed-check", false, "don't ask Grype's database whether distro feeds list the CVEs")
	f.fs.StringVar(&f.keep, "keep", "", "directory to keep the SBOM and Grype output in")
	f.fs.BoolVar(&f.verbose, "verbose", false, "show Syft and Grype progress")
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
	if f.output != "table" && f.output != "json" {
		fmt.Fprintf(stderr, "unknown output format %q (use table or json)\n", f.output)
		return 3
	}
	if len(pos) > 1 || (len(pos) == 0 && f.sbom == "") {
		fmt.Fprintln(stderr, "give exactly one image, or --sbom <file>")
		return 3
	}
	input := ""
	if len(pos) == 1 {
		input = pos[0]
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	rep, err := scan(ctx, f, input, stderr, nil)
	if err != nil {
		fmt.Fprintf(stderr, "whichphp: %v\n", err)
		return 3
	}
	if f.output == "json" {
		if err := report.JSON(stdout, rep); err != nil {
			fmt.Fprintf(stderr, "whichphp: %v\n", err)
			return 3
		}
	} else {
		report.Table(stdout, rep)
	}
	return rep.Action.ExitCode()
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
	if f.output == "json" && !f.verbose {
		return
	}
	fmt.Fprintf(w, format+"\n", a...)
}
