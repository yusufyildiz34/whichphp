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

// Syft colors its errors; the message keeps the words and drops the escapes.
func TestRunStripsColors(t *testing.T) {
	bin := script(t, `printf '[0311] ERROR \033[31mcould not determine source\033[0m\n' >&2; exit 1`)
	_, err := Tools{}.run(context.Background(), bin)
	if err == nil || !strings.Contains(err.Error(), "ERROR could not determine source") || strings.ContainsRune(err.Error(), '\x1b') {
		t.Fatalf("got %q", err)
	}
}

func TestCleanMessage(t *testing.T) {
	for in, want := range map[string]string{
		"\x1b[31mred\x1b[0m": "red",
		"\x1b]8;;https://evil.example\x07link\x1b]8;;\x07": "link",
		"\x1b]0;title\x1b\\text":                           "text",
		"a\x1bMb":                                          "ab",
		"plain [31m":                                       "plain [31m",
		"\x1b[38:2::255:0:0mrgb\x1b(B\x1b7\x1bc\x1b[>4;1m": "rgb",
		"err: \x1b]8;;http://x no space left on device":    "err: 8;;http://x no space left on device",
		"bell\x07 and nul\x00\nnext\tline":                 "bell? and nul?\nnext\tline",
	} {
		if got := cleanMessage(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

// With --verbose the tools' output goes to the terminal, and the error still has its cause.
func TestRunVerboseKeepsTheCause(t *testing.T) {
	bin := script(t, `i=0; while [ $i -lt 2000 ]; do echo "progress line $i padding padding padding" >&2; i=$((i+1)); done; echo "the real cause" >&2; exit 1`)
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	old := os.Stderr
	os.Stderr = devnull
	defer func() { os.Stderr = old }()
	_, err = Tools{Verbose: true}.run(context.Background(), bin)
	if err == nil || !strings.HasSuffix(err.Error(), "the real cause") {
		t.Fatalf("got %v", err)
	}
}
