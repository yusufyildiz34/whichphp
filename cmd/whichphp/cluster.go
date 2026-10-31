package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/yusufyildiz34/whichphp/internal/cluster"
	"github.com/yusufyildiz34/whichphp/internal/registry"
	"github.com/yusufyildiz34/whichphp/internal/report"
	"github.com/yusufyildiz34/whichphp/internal/runner"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

// kubectl runs a read-only kubectl command and returns its standard output. Tests
// replace it.
var kubectl = func(ctx context.Context, args ...string) ([]byte, error) {
	bin := os.Getenv("WHICHPHP_KUBECTL")
	if bin == "" {
		bin = "kubectl"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return nil, fmt.Errorf("kubectl not found (install it or set WHICHPHP_KUBECTL): %w", err)
	}
	var out, errOut bytes.Buffer
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errOut.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("kubectl %s: %s", strings.Join(args, " "), msg)
	}
	return out.Bytes(), nil
}

// clusterTools, clusterScan and clusterResolve check images; tests replace them.
var (
	clusterTools   = func() error { _, err := runner.Find(true); return err }
	clusterContext = func() (context.Context, context.CancelFunc) {
		return signal.NotifyContext(context.Background(), os.Interrupt)
	}
	clusterScan    func(ctx context.Context, f *imageFlags, input, platform string, stderr io.Writer, cache feedCache) (verdict.Report, error)
	clusterResolve func(ctx context.Context, ref string) (string, error)
)

func init() {
	clusterScan = func(ctx context.Context, f *imageFlags, input, platform string, stderr io.Writer, cache feedCache) (verdict.Report, error) {
		g := *f
		g.platform = platform
		return scan(ctx, &g, input, stderr, cache)
	}
	client := registry.NewClient()
	clusterResolve = func(ctx context.Context, ref string) (string, error) {
		r, err := registry.ParseRef(ref)
		if err != nil {
			return "", err
		}
		return client.Digest(ctx, r)
	}
}

func runCluster(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cluster", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var outs outputList
	fs.Var(&outs, "o", "output to write, as `format[=file]`: table or json; repeatable (default table)")
	kubeContext := fs.String("context", "", "kubectl context to read (required, so the current context is never used by accident)")
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig file (default: kubectl's)")
	namespace := fs.String("n", "", "only this namespace (default: all namespaces except kube-system, kube-public and kube-node-lease)")
	selector := fs.String("l", "", "only pods matching this label selector, e.g. app=shop")
	includeSystem := fs.Bool("include-system", false, "also check kube-system, kube-public and kube-node-lease")
	maxDBAge := fs.Int("max-db-age", 7, "days after which Grype's database counts as stale (0 to disable)")
	verbose := fs.Bool("verbose", false, "show Syft and Grype progress")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 3
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "whichphp cluster takes no arguments, got %q\n", fs.Arg(0))
		return 3
	}
	for _, v := range []struct{ name, value string }{{"--context", *kubeContext}, {"--kubeconfig", *kubeconfig}, {"-n", *namespace}, {"-l", *selector}} {
		if strings.HasPrefix(v.value, "-") {
			fmt.Fprintf(stderr, "whichphp: %s %q isn't valid\n", v.name, v.value)
			return 3
		}
	}
	if *kubeContext == "" {
		fmt.Fprintln(stderr, "whichphp: give the cluster with --context <name> (see kubectl config get-contexts)")
		return 3
	}
	if len(outs) == 0 {
		outs = outputList{{format: "table"}}
	}
	for _, o := range outs {
		if o.format != "table" && o.format != "json" {
			fmt.Fprintf(stderr, "whichphp: cluster writes table or json, not %s\n", o.format)
			return 3
		}
	}
	// The restart commands in the report must reach the same cluster from any
	// directory, so they name the kubeconfig kubectl read by its absolute path:
	// --kubeconfig, else the KUBECONFIG list. A list of several files can only be
	// given through the environment, which has no portable syntax on Windows.
	var restartKubeconfig, restartEnv string
	noRestart := false
	var configFiles []string // kept safe from -o
	if *kubeconfig != "" {
		p, err := filepath.Abs(*kubeconfig)
		if err != nil {
			fmt.Fprintf(stderr, "whichphp: --kubeconfig: %v\n", err)
			return 3
		}
		restartKubeconfig = p
		configFiles = append(configFiles, p)
	} else {
		var paths []string
		for _, p := range filepath.SplitList(os.Getenv("KUBECONFIG")) {
			if p == "" {
				continue
			}
			if abs, err := filepath.Abs(p); err == nil {
				p = abs
			}
			paths = append(paths, p)
		}
		configFiles = append(configFiles, paths...)
		switch {
		case len(paths) == 1:
			restartKubeconfig = paths[0]
		case len(paths) > 1 && runtime.GOOS != "windows":
			restartEnv = strings.Join(paths, string(filepath.ListSeparator))
		case len(paths) > 1:
			noRestart = true
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		configFiles = append(configFiles, filepath.Join(home, ".kube", "config"))
	}
	if err := clusterTools(); err != nil {
		fmt.Fprintf(stderr, "whichphp: %s\n", report.Clean(err.Error()))
		return 3
	}
	dests, err := prepareOutputs(outs, configFiles...)
	if err != nil {
		fmt.Fprintf(stderr, "whichphp: %s\n", report.Clean(err.Error()))
		return 3
	}
	defer abort(dests)

	ctx, stop := clusterContext()
	defer stop()

	base := []string{"--context", *kubeContext}
	if *kubeconfig != "" {
		base = append(base, "--kubeconfig", *kubeconfig)
	}
	base = append(base, "--request-timeout=60s")
	podArgs := append(append([]string{}, base...), "get", "pods", "-o", "json")
	if *namespace != "" {
		podArgs = append(podArgs, "-n", *namespace)
	} else {
		podArgs = append(podArgs, "--all-namespaces")
	}
	if *selector != "" {
		podArgs = append(podArgs, "-l", *selector)
	}
	fmt.Fprintf(stderr, "Reading pods in context %s...\n", *kubeContext)
	podsJSON, err := kubectl(ctx, podArgs...)
	if err != nil {
		fmt.Fprintf(stderr, "whichphp: %s\n", report.Clean(err.Error()))
		return 3
	}
	nodesJSON, err := kubectl(ctx, append(append([]string{}, base...), "get", "nodes", "-o", "json")...)
	if err != nil {
		// The report says what that means; the reason goes to stderr only, since it
		// names local paths.
		nodesJSON = nil
		fmt.Fprintf(stderr, "whichphp: couldn't list nodes: %s\n", report.Clean(lastLine(err.Error())))
	}
	var skip []string
	if *namespace == "" && !*includeSystem {
		skip = cluster.SystemNamespaces
	}
	containers, invNotes, err := cluster.Inventory(podsJSON, nodesJSON, cluster.InventoryOptions{SkipNamespaces: skip})
	if err != nil {
		fmt.Fprintf(stderr, "whichphp: %s\n", report.Clean(err.Error()))
		return 3
	}
	if len(containers) == 0 {
		for _, n := range invNotes {
			fmt.Fprintln(stderr, report.Clean(n))
		}
		fmt.Fprintf(stderr, "whichphp: no running pods to check in context %s\n", report.Clean(*kubeContext))
		return 3
	}

	f := newImageFlags(io.Discard)
	f.quiet, f.maxDBAgeDays, f.verbose = true, *maxDBAge, *verbose
	cache := feedCache{}
	scanner := func(ctx context.Context, input, platform string) (verdict.Report, error) {
		return clusterScan(ctx, f, input, platform, stderr, cache)
	}
	res := cluster.Check(ctx, containers, scanner, clusterResolve, cluster.CheckOptions{Context: *kubeContext, Kubeconfig: restartKubeconfig, KubeconfigEnv: restartEnv, NoRestart: noRestart, Log: stderr})
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, "whichphp: interrupted")
		return 3
	}
	res.Version = version
	res.Generated = time.Now().UTC().Format(time.RFC3339)
	res.Notes = append(invNotes, res.Notes...)

	write := func(w io.Writer, format string) error {
		if format == "json" {
			return cluster.JSON(w, res)
		}
		return cluster.Table(w, res)
	}
	for i := range dests {
		d := &dests[i]
		if d.file == nil {
			continue
		}
		err := write(d.file, d.format)
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
			if err := write(stdout, d.format); err != nil {
				fmt.Fprintf(stderr, "whichphp: %s\n", report.Clean(err.Error()))
				return 3
			}
		}
	}
	switch res.Action {
	case cluster.ActionNeeded:
		return 1
	case cluster.ActionUnknown, cluster.ActionError:
		return 2
	}
	return 0
}

// lastLine returns the last non-empty line of a kubectl error, which says why.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	s = strings.TrimSpace(lines[len(lines)-1])
	if len(s) > 500 {
		s = s[:500] + "…"
	}
	return s
}
