// Package runner invokes Syft and Grype. whichphp never runs the image itself: Syft
// reads the image layers, and Grype matches the resulting SBOM against its database.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/yusufyildiz34/whichphp/internal/phpini"
)

// Tools holds the paths of the external tools.
type Tools struct {
	Syft  string
	Grype string
	// Verbose streams the tools' progress output to stderr.
	Verbose bool
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

// SBOM runs Syft on the source and writes Syft JSON to out.
func (t Tools) SBOM(ctx context.Context, source, platform, dir string) (string, error) {
	cfg := filepath.Join(dir, "syft.yaml")
	if err := os.WriteFile(cfg, []byte(syftConfig()), 0o600); err != nil {
		return "", err
	}
	out := filepath.Join(dir, "sbom.syft.json")
	args := []string{"scan", source, "-c", cfg, "-o", "json=" + out}
	if platform != "" {
		args = append(args, "--platform", platform)
	}
	// No -q: quiet mode also hides the error message. Output is captured either way.
	if _, err := t.run(ctx, t.Syft, args...); err != nil {
		return "", fmt.Errorf("syft failed: %w", err)
	}
	return out, nil
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

func (t Tools) run(ctx context.Context, bin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "SYFT_CHECK_FOR_APP_UPDATE=false", "GRYPE_CHECK_FOR_APP_UPDATE=false")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	if t.Verbose {
		cmd.Stderr = os.Stderr
	} else {
		cmd.Stderr = &stderr
	}
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		// The tools print the error last, after any warnings.
		if len(msg) > 2000 {
			msg = msg[len(msg)-2000:]
		}
		if msg != "" {
			return stdout.Bytes(), fmt.Errorf("%w: %s", err, msg)
		}
		return stdout.Bytes(), err
	}
	return stdout.Bytes(), nil
}
