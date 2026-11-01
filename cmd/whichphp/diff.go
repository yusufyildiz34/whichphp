package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/yusufyildiz34/whichphp/internal/diff"
	"github.com/yusufyildiz34/whichphp/internal/report"
	"github.com/yusufyildiz34/whichphp/internal/runner"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

const diffUsage = `Usage: whichphp diff <before> <after> [flags]

Compares the PHP in two images, before and after a change such as a rebuild:
the PHP builds added, removed and changed, each CVE verdict, the effective
session.upload_progress.enabled, the image digests and creation dates, and
the overall result.

<before> and <after> are each a whichphp JSON report or an image:
  - An existing file that holds a JSON report, as "whichphp image
    -o json=<file>" writes it, is read, not scanned again.
  - Anything else is scanned as "whichphp image" scans it: nginx:latest,
    docker:app:tag, docker-archive:img.tar, img.tar, ...
  A file that starts like JSON but isn't a whichphp image report, and any
  name ending in .json that isn't one, is an error and is never scanned.

PHP builds are paired by name and SAPI; then by name without the PHP
version in it, so php8.3-fpm and php8.4-fpm are the same FPM build,
upgraded; then by SAPI alone, when each image has one build of that SAPI
left. Where several builds could pair, the closest PHP versions pair first.
The rest were added or removed.

The result says "Fixed by this change" only when the after image is OK with
every fix proven. No PHP found in the after image, or a distro backport whose
feed coverage wasn't confirmed, isn't proof of a fix.

Exit codes come from the after image: 0 fixed or no PHP, 1 action needed,
2 unknown, 3 error.

Flags (--platform, --no-grype, --skip-feed-check, --max-db-age and --verbose
apply only to arguments that are scanned):
`

func runDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), diffUsage)
		fs.PrintDefaults()
	}
	var outs outputList
	fs.Var(&outs, "o", "output to write, as `format[=file]`: table or json; repeatable (default table)")
	platform := fs.String("platform", "", "platform of the images to scan, e.g. linux/arm64")
	noGrype := fs.Bool("no-grype", false, "don't use Grype; distro packages get UNKNOWN")
	skipFeedCheck := fs.Bool("skip-feed-check", false, "don't ask Grype's database whether distro feeds list the CVEs")
	maxDBAge := fs.Int("max-db-age", 7, "days after which Grype's database counts as stale (0 to disable)")
	failOnMitigation := fs.Bool("fail-on-mitigation", false, "count session.upload_progress on as action needed, in both images (CVE-2026-115560)")
	verbose := fs.Bool("verbose", false, "show Syft and Grype progress")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 3
	}
	if len(pos) != 2 {
		fmt.Fprintln(stderr, "whichphp: give two images or reports: whichphp diff <before> <after>")
		return 3
	}
	for _, p := range pos {
		if strings.HasPrefix(p, "-") {
			fmt.Fprintf(stderr, "whichphp: %q isn't an image reference or report file\n", p)
			return 3
		}
	}
	if len(outs) == 0 {
		outs = outputList{{format: "table"}}
	}
	for _, o := range outs {
		if o.format != "table" && o.format != "json" {
			fmt.Fprintf(stderr, "whichphp: diff writes table or json, not %s\n", o.format)
			return 3
		}
	}
	// An output must not overwrite an argument, a report or an archive alike.
	var inputs []string
	for _, p := range pos {
		inputs = append(inputs, runner.LocalPath(p))
	}
	dests, err := prepareOutputs(outs, inputs...)
	if err != nil {
		fmt.Fprintf(stderr, "whichphp: %s\n", report.Clean(err.Error()))
		return 3
	}
	defer abort(dests)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	f := newImageFlags(io.Discard)
	f.outputs, f.platform, f.noGrype, f.skipFeedCheck = outs, *platform, *noGrype, *skipFeedCheck
	f.maxDBAgeDays, f.verbose = *maxDBAge, *verbose
	cache := feedCache{}
	var reps [2]verdict.Report
	for i, arg := range pos {
		rep, ok, err := diff.ReadReport(arg)
		if err == nil && !ok {
			rep, err = scan(ctx, f, arg, stderr, cache)
		}
		if err != nil {
			fmt.Fprintf(stderr, "whichphp: %s: %s\n", [2]string{"before", "after"}[i], report.Clean(err.Error()))
			return 3
		}
		reps[i] = rep
	}

	d := diff.Compare(reps[0], reps[1], diff.Options{FailOnMitigation: *failOnMitigation, Version: version})
	write := func(w io.Writer, format string) error {
		if format == "json" {
			return diff.JSON(w, d)
		}
		return diff.Table(w, d)
	}
	if err := writeAll(dests, stdout, write); err != nil {
		fmt.Fprintf(stderr, "whichphp: %s\n", report.Clean(err.Error()))
		return 3
	}
	return d.ExitCode()
}
