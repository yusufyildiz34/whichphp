// Package runner invokes Syft and Grype. whichphp never runs the image itself: Syft
// reads the image layers, and Grype matches the resulting SBOM against its database.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/yusufyildiz34/whichphp/internal/phpini"
)

// Tools holds the paths of the external tools.
type Tools struct {
	Syft  string
	Grype string
	// Verbose streams the tools' progress output to stderr.
	Verbose bool
	// Retrying, when set, is told why Syft runs a second time.
	Retrying func(cause string)
}

// Find locates syft and grype, honoring WHICHPHP_SYFT and WHICHPHP_GRYPE.
func Find(needGrype bool) (Tools, error) {
	t := Tools{Syft: os.Getenv("WHICHPHP_SYFT"), Grype: os.Getenv("WHICHPHP_GRYPE")}
	var missing []string
	if t.Syft == "" {
		if p, err := exec.LookPath("syft"); err == nil {
			t.Syft = p
		} else {
			missing = append(missing, "syft")
		}
	}
	if needGrype && t.Grype == "" {
		if p, err := exec.LookPath("grype"); err == nil {
			t.Grype = p
		} else {
			missing = append(missing, "grype")
		}
	}
	if len(missing) > 0 {
		return t, fmt.Errorf("%s not found on PATH. Install from https://github.com/anchore/syft and https://github.com/anchore/grype, or set WHICHPHP_SYFT / WHICHPHP_GRYPE",
			strings.Join(missing, " and "))
	}
	return t, nil
}

// syftConfig asks Syft to capture the contents of PHP configuration files.
func syftConfig() string {
	var b strings.Builder
	b.WriteString("file:\n  content:\n    skip-files-above-size: 262144\n    globs:\n")
	for _, g := range phpini.Globs {
		fmt.Fprintf(&b, "      - %q\n", g)
	}
	return b.String()
}

// SBOM runs Syft on the source and returns the path of the Syft JSON it wrote in dir.
// When the run fails because a download was cut off (see CutOff), Syft runs once
// more, after t.Retrying is told why; retried is then that cause.
func (t Tools) SBOM(ctx context.Context, source, platform, dir string) (sbom, retried string, err error) {
	cfg := filepath.Join(dir, "syft.yaml")
	if err := os.WriteFile(cfg, []byte(syftConfig()), 0o600); err != nil {
		return "", "", err
	}
	out := filepath.Join(dir, "sbom.syft.json")
	args := []string{"scan", "-c", cfg, "-o", "json=" + out}
	if platform != "" {
		args = append(args, "--platform", platform)
	}
	// "--" so a source can never be read as a Syft flag.
	args = append(args, "--", source)
	// No -q: quiet mode also hides the error message. Output is captured either way.
	_, err = t.run(ctx, t.Syft, args...)
	if err == nil {
		return out, "", nil
	}
	cause := CutOff(source, err)
	if cause == "" || ctx.Err() != nil {
		return "", "", fmt.Errorf("syft failed: %w", err)
	}
	if t.Retrying != nil {
		t.Retrying(cause)
	}
	if _, err := t.run(ctx, t.Syft, args...); err != nil {
		return "", cause, fmt.Errorf("syft failed again after its first download was cut off (%s): %w", cause, err)
	}
	return out, cause, nil
}

// cutOffCauses are the errors of a transfer that stopped partway, which a second try
// often gets past: a proxy or registry that drops long downloads (unexpected EOF), a
// reset connection, or a handshake or read that timed out. Anything else, such as a
// missing image, a refused login or a full disk, fails the same way again.
var cutOffCauses = []string{"unexpected EOF", "connection reset by peer", "TLS handshake timeout", "i/o timeout"}

// localSources are Syft sources read from local files, which no download can cut off.
var localSources = []string{"docker-archive:", "oci-archive:", "oci-dir:", "dir:", "file:", "singularity:"}

// LocalPath returns the file or directory a Syft source for local files reads, without
// its scheme ("old.tar" for "docker-archive:old.tar"), or the source as it is.
func LocalPath(source string) string {
	for _, p := range localSources {
		if rest, ok := strings.CutPrefix(source, p); ok {
			return rest
		}
	}
	return source
}

// CutOff returns the cause when Syft's error for this source says that a download
// was cut off or reset, and "" otherwise. Only the error Syft ends with counts: its
// warnings about files inside the image, logged before it, can say "unexpected EOF"
// too. A source that names an existing path is a local file, whichever scheme Syft
// reads it with, and no download can cut that off.
func CutOff(source string, err error) string {
	if err == nil {
		return ""
	}
	for _, p := range localSources {
		if strings.HasPrefix(source, p) {
			return ""
		}
	}
	if _, statErr := os.Stat(source); statErr == nil {
		return ""
	}
	msg := err.Error()
	var te *toolError
	if errors.As(err, &te) {
		msg = te.msg
	}
	msg = finalError(msg)
	for _, c := range cutOffCauses {
		if strings.Contains(msg, c) {
			return c
		}
	}
	return ""
}

// logLineRE matches a line Syft logs, such as "[0012]  WARN ...", and its level.
var logLineRE = regexp.MustCompile(`^\s*\[\d+\]\s+([A-Z]+)\b`)

// finalError returns the end of a tool's output that holds its error: from the last
// line it logs, if that is an error, or else from the line after it. Syft logs its
// warnings and progress first and its error last.
func finalError(msg string) string {
	lines := strings.Split(msg, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if m := logLineRE.FindStringSubmatch(lines[i]); m != nil {
			if m[1] == "ERROR" {
				return strings.Join(lines[i:], "\n")
			}
			return strings.Join(lines[i+1:], "\n")
		}
	}
	return msg
}

// Match runs Grype on a Syft JSON SBOM and writes Grype JSON to out.
func (t Tools) Match(ctx context.Context, sbom, dir string) (string, error) {
	out := filepath.Join(dir, "grype.json")
	args := []string{"sbom:" + sbom, "-o", "json", "--file", out}
	if _, err := t.run(ctx, t.Grype, args...); err != nil {
		var exit *exec.ExitError
		// Grype exits non-zero only with --fail-on; any other failure is real.
		if !errors.As(err, &exit) {
			return "", fmt.Errorf("grype failed: %w", err)
		}
		if _, statErr := os.Stat(out); statErr != nil {
			return "", fmt.Errorf("grype failed: %w", err)
		}
	}
	return out, nil
}

// DBStatus returns `grype db status -o json` output.
func (t Tools) DBStatus(ctx context.Context) ([]byte, error) {
	return t.run(ctx, t.Grype, "db", "status", "-o", "json")
}

// DBSearch returns `grype db search --vuln <id> [--distro <distro>] -o json` output.
func (t Tools) DBSearch(ctx context.Context, id, distro string) ([]byte, error) {
	args := []string{"db", "search", "--vuln", id, "-o", "json"}
	if distro != "" {
		args = append(args, "--distro", distro)
	}
	return t.run(ctx, t.Grype, args...)
}

// ansiRE matches terminal escape sequences, which the tools use to color errors:
// CSI sequences, terminated OSC sequences, nF escapes such as ESC ( B, and the other
// two-byte escapes. An unterminated OSC loses only its ESC ], so the text after it,
// often the cause, stays.
var ansiRE = regexp.MustCompile("\x1b(\\[[0-?]*[ -/]*[@-~]|\\][^\x07\x1b]*(\x07|\x1b\\\\)|[ -/]+[0-~]|[0-Z\\\\-~])")

// cleanMessage removes escape sequences and turns other control characters, except
// newlines and tabs, into "?".
func cleanMessage(s string) string {
	return strings.Map(func(r rune) rune {
		if r != '\n' && r != '\t' && unicode.IsControl(r) {
			return '?'
		}
		return r
	}, ansiRE.ReplaceAllString(s, ""))
}

// ignoreErrors keeps a broken terminal from stopping the copy of a tool's output.
type ignoreErrors struct{ w io.Writer }

func (i ignoreErrors) Write(p []byte) (int, error) {
	_, _ = i.w.Write(p) // the terminal is best effort; the tail must still fill
	return len(p), nil
}

// tail keeps the last max bytes written to it.
type tail struct {
	buf []byte
	max int
}

func (t *tail) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = append(t.buf[:0], t.buf[len(t.buf)-t.max:]...)
	}
	return len(p), nil
}

// toolError is a tool's failure with the end of its output, the message.
type toolError struct {
	err error
	msg string
}

func (e *toolError) Error() string { return e.err.Error() + ": " + e.msg }
func (e *toolError) Unwrap() error { return e.err }

func (t Tools) run(ctx context.Context, bin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "SYFT_CHECK_FOR_APP_UPDATE=false", "GRYPE_CHECK_FOR_APP_UPDATE=false", "NO_COLOR=1")
	var stdout bytes.Buffer
	stderr := &tail{max: 64 << 10}
	cmd.Stdout = &stdout
	cmd.Stderr = stderr
	if t.Verbose {
		// Show the progress, and still keep the end for the error message.
		cmd.Stderr = io.MultiWriter(stderr, ignoreErrors{os.Stderr})
	}
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(cleanMessage(string(stderr.buf)))
		if msg == "" {
			msg = strings.TrimSpace(cleanMessage(stdout.String()))
		}
		// The tools print the error last, after any warnings.
		if len(msg) > 2000 {
			msg = msg[len(msg)-2000:]
		}
		if msg != "" {
			return stdout.Bytes(), &toolError{err: err, msg: msg}
		}
		return stdout.Bytes(), err
	}
	return stdout.Bytes(), nil
}
