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
	"sort"
	"strings"
	"time"

	"github.com/yusufyildiz34/whichphp/internal/index"
	"github.com/yusufyildiz34/whichphp/internal/registry"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

func runIndex(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("index", flag.ContinueOnError)
	fs.SetOutput(stderr)
	images := fs.String("images", "index/images.csv", "tracked images (CSV: ref,kind,owner,note)")
	data := fs.String("data", "data", "directory for index.json, history.jsonl and badges/")
	platforms := fs.String("platforms", "linux/amd64,linux/arm64", "comma-separated platforms to index")
	rescanDays := fs.Int("rescan-days", 7, "rescan unchanged tags after this many days (distro data can change)")
	maxScans := fs.Int("max-scans", 0, "maximum image scans in this run (0 for no limit)")
	maxDBAge := fs.Int("max-db-age", 7, "days after which Grype's database counts as stale")
	verbose := fs.Bool("verbose", false, "show Syft and Grype progress")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 3
	}

	imgs, err := index.LoadImages(*images)
	if err != nil {
		fmt.Fprintf(stderr, "whichphp: %v\n", err)
		return 3
	}
	if err := os.MkdirAll(*data, 0o755); err != nil {
		fmt.Fprintf(stderr, "whichphp: %v\n", err)
		return 3
	}
	indexPath := filepath.Join(*data, "index.json")
	prev, err := index.Load(indexPath)
	if err != nil {
		fmt.Fprintf(stderr, "whichphp: %v\n", err)
		return 3
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	client := registry.NewClient()
	resolve := func(ctx context.Context, ref string) (string, error) {
		r, err := registry.ParseRef(ref)
		if err != nil {
			return "", err
		}
		return client.Digest(ctx, r)
	}
	cache := feedCache{}
	scanOne := func(ctx context.Context, ref, platform string) (verdict.Report, error) {
		f := newImageFlags(io.Discard)
		f.output, f.platform, f.maxDBAgeDays, f.verbose = "json", platform, *maxDBAge, *verbose
		return scan(ctx, f, ref, stderr, cache)
	}

	var plats []string
	for _, p := range strings.Split(*platforms, ",") {
		if p = strings.TrimSpace(p); p != "" {
			plats = append(plats, p)
		}
	}
	next, changes := index.Update(ctx, imgs, prev, resolve, scanOne, index.Options{
		Platforms:   plats,
		RescanAfter: time.Duration(*rescanDays) * 24 * time.Hour,
		MaxScans:    *maxScans,
		Log:         stderr,
		Tool:        "whichphp " + version,
	})
	if err := index.Save(indexPath, next); err != nil {
		fmt.Fprintf(stderr, "whichphp: %v\n", err)
		return 3
	}
	if err := index.AppendHistory(filepath.Join(*data, "history.jsonl"), changes); err != nil {
		fmt.Fprintf(stderr, "whichphp: %v\n", err)
		return 3
	}
	if err := index.SaveBadges(filepath.Join(*data, "badges"), index.Badges(next)); err != nil {
		fmt.Fprintf(stderr, "whichphp: %v\n", err)
		return 3
	}

	counts := map[string]int{}
	for _, e := range next.Entries {
		k := e.Action
		if e.Error != "" {
			k = "ERROR"
		}
		counts[k]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(stdout, "Indexed %d entries (%d changes):", len(next.Entries), len(changes))
	for _, k := range keys {
		fmt.Fprintf(stdout, " %s=%d", k, counts[k])
	}
	fmt.Fprintln(stdout)
	for _, n := range next.Notes {
		fmt.Fprintf(stdout, "Note: %s\n", n)
	}
	return 0
}
