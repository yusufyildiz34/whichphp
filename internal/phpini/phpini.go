// Package phpini works out the image-default values of the PHP settings that matter for
// PHP2Shell, from configuration files read out of the image (never by running PHP).
package phpini

import (
	"path"
	"regexp"
	"sort"
	"strings"
)

// Directives whichphp evaluates.
const (
	UploadProgress       = "session.upload_progress.enabled"
	FatalErrorBacktraces = "fatal_error_backtraces"
)

var directives = map[string]bool{UploadProgress: true, FatalErrorBacktraces: true}

// Globs are the files whichphp asks Syft to capture.
var Globs = []string{
	"**/php.ini",
	"**/conf.d/*.ini",
	"**/php.d/*.ini",
	"**/php-fpm.conf",
	"**/php-fpm.d/*.conf",
	"**/pool.d/*.conf",
}

// configPath limits evaluation to PHP configuration locations.
var configPath = regexp.MustCompile(`(?i)(^|/)(etc|usr/local/etc|opt)/.*(php|fpm).*\.(ini|conf)$`)

var (
	iniLine  = regexp.MustCompile(`^\s*([A-Za-z0-9_.]+)\s*=\s*(.*)$`)
	poolLine = regexp.MustCompile(`^\s*php_(admin_)?(value|flag)\[([A-Za-z0-9_.]+)\]\s*=\s*(.*)$`)
)

// Setting is the effective image default for one directive.
type Setting struct {
	// Effective is "on", "off", "off-in-fpm-pool" or "unknown".
	Effective string `json:"effective"`
	// Why explains where the value comes from.
	Why string `json:"why"`
	// SetIn lists the files that set the directive.
	SetIn []string `json:"setIn,omitempty"`
}

// Result is the evaluation of all captured configuration files.
type Result struct {
	Settings    map[string]Setting `json:"settings"`
	FilesSeen   []string           `json:"filesSeen"`
	ContentSeen bool               `json:"-"`
}

type tree struct {
	root    string
	label   string
	entries []entry
}

type entry struct {
	order int
	name  string
	path  string
	lines []string
}

type poolOverride struct {
	file, directive string
	value           *bool
}

// Evaluate computes effective settings from file contents keyed by path. contentSeen
// tells whether the SBOM was produced with file-content capture; without it the
// settings can't be known.
func Evaluate(files map[string]string, contentSeen bool) Result {
	res := Result{Settings: map[string]Setting{}, ContentSeen: contentSeen}
	if !contentSeen {
		for d := range directives {
			res.Settings[d] = Setting{Effective: "unknown", Why: "the SBOM has no configuration file contents (scan with whichphp, or Syft with file-content globs)"}
		}
		return res
	}

	// Read the files in a fixed order, so the result never depends on map order. When
	// two names mean the same path ("etc/php.ini" and "/etc/php.ini"), the absolute
	// name's contents win.
	byPath := map[string]string{}
	var paths []string
	for name, content := range files {
		p := "/" + strings.TrimPrefix(name, "/")
		if _, dup := byPath[p]; !dup {
			paths = append(paths, p)
		} else if name != p {
			continue
		}
		byPath[p] = content
	}
	sort.Strings(paths)

	trees := map[string]*tree{}
	var pools []poolOverride
	for _, p := range paths {
		content := byPath[p]
		if !configPath.MatchString(p) {
			continue
		}
		res.FilesSeen = append(res.FilesSeen, p)
		lines := cleanLines(content)
		base, parent := path.Base(p), path.Dir(p)
		switch {
		case strings.HasSuffix(p, ".ini"):
			var root string
			var order int
			if base == "php.ini" {
				root, order = parent, 0
			} else if b := path.Base(parent); b == "conf.d" || b == "php.d" {
				root, order = path.Dir(parent), 1
			} else {
				continue
			}
			t := trees[root]
			if t == nil {
				t = &tree{root: root, label: treeLabel(root)}
				trees[root] = t
			}
			t.entries = append(t.entries, entry{order: order, name: base, path: p, lines: lines})
		case strings.HasSuffix(p, ".conf"):
			for _, l := range lines {
				m := poolLine.FindStringSubmatch(l)
				if m == nil {
					continue
				}
				d := strings.ToLower(m[3])
				if directives[d] {
					pools = append(pools, poolOverride{file: p, directive: d, value: parseBool(m[4])})
				}
			}
		}
	}
	sort.Strings(res.FilesSeen)

	type treeValue struct {
		label string
		value *bool
		setIn string
	}
	values := map[string][]treeValue{}
	roots := make([]string, 0, len(trees))
	for r := range trees {
		roots = append(roots, r)
	}
	sort.Strings(roots)
	for _, r := range roots {
		t := trees[r]
		sort.Slice(t.entries, func(i, j int) bool {
			if t.entries[i].order != t.entries[j].order {
				return t.entries[i].order < t.entries[j].order
			}
			return t.entries[i].name < t.entries[j].name
		})
		cur := map[string]treeValue{}
		for d := range directives {
			cur[d] = treeValue{label: t.label}
		}
		for _, e := range t.entries {
			for _, l := range e.lines {
				m := iniLine.FindStringSubmatch(l)
				if m == nil {
					continue
				}
				d := strings.ToLower(m[1])
				if directives[d] {
					cur[d] = treeValue{label: t.label, value: parseBool(m[2]), setIn: e.path}
				}
			}
		}
		for d, v := range cur {
			values[d] = append(values[d], v)
		}
	}

	for d := range directives {
		all := values[d]
		var serving []treeValue
		for _, v := range all {
			if v.label != "cli" {
				serving = append(serving, v)
			}
		}
		if len(serving) == 0 {
			serving = all
		}
		var s Setting
		on := false
		if len(serving) == 0 {
			on = true
			s.Why = "no php.ini or conf.d files in the image, so PHP's compiled default (on) applies"
		} else {
			for _, v := range serving {
				if v.value == nil || *v.value {
					on = true
				}
				if v.setIn != "" {
					s.SetIn = append(s.SetIn, v.setIn)
				}
			}
			if on {
				s.Why = "not turned off in the php.ini/conf.d files that serve web traffic"
			} else {
				s.Why = "turned off in every php.ini/conf.d tree that serves web traffic"
			}
		}
		poolOff := false
		for _, p := range pools {
			if p.directive == d && p.value != nil && !*p.value {
				poolOff = true
				s.SetIn = append(s.SetIn, p.file)
			}
		}
		switch {
		case on && poolOff:
			s.Effective = "off-in-fpm-pool"
			s.Why = "on in php.ini/conf.d, but turned off in an FPM pool file"
		case on:
			s.Effective = "on"
		default:
			s.Effective = "off"
		}
		res.Settings[d] = s
	}
	return res
}

func cleanLines(content string) []string {
	var out []string
	for _, l := range strings.Split(content, "\n") {
		l = strings.TrimRight(l, "\r \t")
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, ";") || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}

func treeLabel(root string) string {
	r := "/" + root
	switch {
	case strings.Contains(r, "/cli"):
		return "cli"
	case strings.Contains(r, "/fpm"):
		return "fpm"
	case strings.Contains(r, "apache2"):
		return "apache2"
	}
	return "shared"
}

func parseBool(v string) *bool {
	v = strings.TrimSpace(strings.SplitN(v, ";", 2)[0])
	v = strings.ToLower(strings.Trim(v, `"'`))
	t, f := true, false
	switch v {
	case "0", "off", "false", "no", "none", "":
		return &f
	case "1", "on", "true", "yes":
		return &t
	}
	return nil
}
