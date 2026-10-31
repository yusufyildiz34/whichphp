package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func script(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunReportsTheToolsError(t *testing.T) {
	bin := script(t, `echo "warning: something minor" >&2; echo "could not fetch the image: TOOMANYREQUESTS" >&2; exit 1`)
	_, err := Tools{}.run(context.Background(), bin)
	if err == nil || !strings.Contains(err.Error(), "TOOMANYREQUESTS") {
		t.Fatalf("got %v", err)
	}
}

func TestRunFallsBackToStdout(t *testing.T) {
	bin := script(t, `echo "error printed to stdout"; exit 1`)
	_, err := Tools{}.run(context.Background(), bin)
	if err == nil || !strings.Contains(err.Error(), "error printed to stdout") {
		t.Fatalf("got %v", err)
	}
}

func TestRunDisablesUpdateChecks(t *testing.T) {
	bin := script(t, `echo "$SYFT_CHECK_FOR_APP_UPDATE $GRYPE_CHECK_FOR_APP_UPDATE"`)
	out, err := Tools{}.run(context.Background(), bin)
	if err != nil || strings.TrimSpace(string(out)) != "false false" {
		t.Fatalf("got %q, %v", out, err)
	}
}
