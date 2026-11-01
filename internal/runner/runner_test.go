package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
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

// fakeSyft fails its first runs with the given messages, one per run, and then
// writes an empty SBOM. It returns its path and a function that counts its runs.
func fakeSyft(t *testing.T, failures ...string) (string, func() int) {
	t.Helper()
	count := filepath.Join(t.TempDir(), "count")
	body := `n=$(cat '` + count + `' 2>/dev/null || echo 0); echo $((n+1)) > '` + count + `'` + "\n"
	for i, f := range failures {
		body += `if [ "$n" = ` + strconv.Itoa(i) + ` ]; then echo '` + f + `' >&2; exit 1; fi` + "\n"
	}
	body += `for a; do case "$a" in json=*) echo '{}' > "${a#json=}";; esac; done`
	runs := func() int {
		b, _ := os.ReadFile(count)
		n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		return n
	}
	return script(t, body), runs
}

// A download cut off partway is read once more, and the caller hears why.
func TestSBOMRetriesACutOffDownload(t *testing.T) {
	syft, runs := fakeSyft(t, "[0300] ERROR could not fetch image: read tcp 10.0.0.2:51234->1.2.3.4:443: unexpected EOF")
	var told []string
	tools := Tools{Syft: syft, Retrying: func(cause string) { told = append(told, cause) }}
	out, retried, err := tools.SBOM(context.Background(), "registry:php@sha256:abc", "linux/amd64", t.TempDir())
	if err != nil || retried != "unexpected EOF" || runs() != 2 || len(told) != 1 || told[0] != "unexpected EOF" {
		t.Fatalf("err %v, retried %q, %d runs, told %q", err, retried, runs(), told)
	}
	if b, err := os.ReadFile(out); err != nil || strings.TrimSpace(string(b)) != "{}" {
		t.Errorf("SBOM: %q, %v", b, err)
	}
}

// A second failure fails the scan, and the error says it was tried twice.
func TestSBOMRetriesOnlyOnce(t *testing.T) {
	syft, runs := fakeSyft(t, "read: connection reset by peer", "net/http: TLS handshake timeout", "never reached")
	_, retried, err := Tools{Syft: syft}.SBOM(context.Background(), "php:8.4", "", t.TempDir())
	if err == nil || runs() != 2 || retried != "connection reset by peer" ||
		!strings.Contains(err.Error(), "again after its first download was cut off (connection reset by peer)") || !strings.Contains(err.Error(), "TLS handshake timeout") {
		t.Fatalf("err %v, retried %q, %d runs", err, retried, runs())
	}
}

// Other failures, and local files, aren't tried again.
func TestSBOMDoesNotRetryOtherFailures(t *testing.T) {
	// An archive named without a scheme is a local file too.
	dir := t.TempDir()
	archive := filepath.Join(dir, "app.tar")
	if err := os.WriteFile(archive, []byte("app/"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	for source, msg := range map[string]string{
		"registry:php:8.4":            "MANIFEST_UNKNOWN: manifest unknown",
		"registry:ghcr.io/acme/app:1": "401 Unauthorized",
		"docker-archive:image.tar":    "unexpected EOF",
		"oci-dir:./layout":            "i/o timeout",
		archive:                       "unexpected EOF",
		"app.tar":                     "unexpected EOF",
		"./app.tar":                   "read: connection reset by peer",
	} {
		syft, runs := fakeSyft(t, msg, msg)
		tools := Tools{Syft: syft, Retrying: func(string) { t.Errorf("%s: retried", source) }}
		if _, retried, err := tools.SBOM(context.Background(), source, "", t.TempDir()); err == nil || retried != "" || runs() != 1 {
			t.Errorf("%s: err %v, retried %q, %d runs", source, err, retried, runs())
		}
	}
}

func TestCutOff(t *testing.T) {
	for msg, want := range map[string]string{
		"syft failed: exit status 1: could not fetch image: unexpected EOF":       "unexpected EOF",
		"Get https://registry-1.docker.io/v2/: dial tcp 1.2.3.4:443: i/o timeout": "i/o timeout",
		"net/http: TLS handshake timeout":                                         "TLS handshake timeout",
		"read tcp 10.0.0.2:1->1.2.3.4:443: read: connection reset by peer":        "connection reset by peer",
		"unexpected end of JSON input":                                            "",
		"failed to get image: no space left on device":                            "",
		"context deadline exceeded":                                               "",
		"Error response from daemon: No such image: php:8.4":                      "",
	} {
		if got := CutOff("registry:php:8.4", errors.New(msg)); got != want {
			t.Errorf("CutOff(%q) = %q, want %q", msg, got, want)
		}
	}
	if CutOff("registry:php:8.4", nil) != "" || CutOff("dir:/src", errors.New("unexpected EOF")) != "" {
		t.Error("no error, or a local source, must not count as a cut-off download")
	}
}

// Only the error Syft ends with counts, not its warnings about files in the image.
func TestCutOffReadsOnlyTheFinalError(t *testing.T) {
	warning := "[0012]  WARN unable to read /usr/lib/php/20230831/broken.so: unexpected EOF"
	for msg, want := range map[string]string{
		warning + "\n[0300] ERROR could not fetch image: MANIFEST_UNKNOWN: manifest unknown":               "",
		warning + "\n1 error occurred:\n\t* failed to catalog: no space left on device":                    "",
		warning + "\n[0300] ERROR could not fetch image: read tcp 10.0.0.2:1->1.2.3.4:443: unexpected EOF": "unexpected EOF",
		warning + "\n1 error occurred:\n\t* could not fetch image: read: connection reset by peer":         "connection reset by peer",
		"[0001]  INFO pulling image\n[0300] ERROR could not fetch image: unexpected EOF\n  details follow": "unexpected EOF",
		warning: "",
	} {
		if got := CutOff("registry:php:8.4", errors.New(msg)); got != want {
			t.Errorf("CutOff(%q) = %q, want %q", msg, got, want)
		}
	}

	// The same through a real run, where the error carries the exit status first.
	syft := script(t, `printf '%s\n' '`+warning+`' '[0300] ERROR could not fetch image: MANIFEST_UNKNOWN' >&2; exit 1`)
	tools := Tools{Syft: syft, Retrying: func(string) { t.Error("retried on a warning") }}
	if _, retried, err := tools.SBOM(context.Background(), "registry:php:8.4", "", t.TempDir()); err == nil || retried != "" || !strings.Contains(err.Error(), "MANIFEST_UNKNOWN") {
		t.Errorf("err %v, retried %q", err, retried)
	}
}
