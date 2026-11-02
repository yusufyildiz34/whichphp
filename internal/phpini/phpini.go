// Package phpini works out the image-default values of the PHP settings that matter for
// PHP2Shell, from configuration files read out of the image (never by running PHP).
package phpini

import (
	"path"
	"regexp"
	"slices"
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
	iniLine     = regexp.MustCompile(`^\s*([A-Za-z0-9_.]+)\s*=\s*(.*)$`)
	poolLine    = regexp.MustCompile(`^\s*php_(admin_)?(value|flag)\[([A-Za-z0-9_.]+)\]\s*=\s*(.*)$`)
	sectionLine = regexp.MustCompile(`^\s*\[\s*([^\]]*?)\s*\]\s*([;#].*)?$`)
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
	file, pool, directive string
	value                 *bool
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
	poolNames := map[string]bool{}
	for _, p := range paths {
		content := byPath[p]
		if !configPath.MatchString(p) {
			continue
		}
		res.FilesSeen = append(res.FilesSeen, p)
		lines := cleanLines(content)
		switch kind, root, order := classify(p); kind {
		case iniFile:
			t := trees[root]
			if t == nil {
				t = &tree{root: root, label: treeLabel(root)}
				trees[root] = t
			}
			t.entries = append(t.entries, entry{order: order, name: path.Base(p), path: p, lines: lines})
		case poolFile:
			// A directive belongs to the pool whose [section] it sits in. FPM joins
			// sections of the same name into one pool, and [global] isn't a pool.
			pool := ""
			for _, l := range lines {
				if m := sectionLine.FindStringSubmatch(l); m != nil {
					pool = ""
					if name := strings.ToLower(m[1]); name != "global" {
						pool = "[" + name + "]"
						poolNames[pool] = true
					}
					continue
				}
				m := poolLine.FindStringSubmatch(l)
				if m == nil {
					continue
				}
				d := strings.ToLower(m[3])
				if directives[d] {
					pools = append(pools, poolOverride{file: p, pool: pool, directive: d, value: parseBool(m[4])})
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
		// Each FPM pool serves with its own value, or with the php.ini/conf.d value
		// when it sets none. A pool that turns the directive on serves with it on,
		// and so does one that sets a value that can't be read, as in php.ini.
		byPool := map[string][]*bool{}
		for _, p := range pools {
			if p.directive != d {
				continue
			}
			byPool[p.pool] = append(byPool[p.pool], p.value)
			if !slices.Contains(s.SetIn, p.file) {
				s.SetIn = append(s.SetIn, p.file)
			}
		}
		poolOff, poolOn, inherits := false, false, false
		for _, values := range byPool {
			if slices.ContainsFunc(values, func(v *bool) bool { return v == nil || *v }) {
				poolOn = true
			} else {
				poolOff = true
			}
		}
		for name := range poolNames {
			if _, set := byPool[name]; !set {
				inherits = true
			}
		}
		switch {
		case poolOn && poolOff:
			s.Effective = "on"
			s.Why = "turned on in one FPM pool and off in another"
		case poolOn && !on:
			s.Effective = "on"
			s.Why = "off in php.ini/conf.d, but an FPM pool turns it on or sets a value whichphp can't read"
		case on && poolOff && inherits:
			s.Effective = "on"
			s.Why = "on in php.ini/conf.d; an FPM pool turns it off, but another pool doesn't"
		case on && poolOff:
			s.Effective = "off-in-fpm-pool"
			s.Why = "on in php.ini/conf.d, but turned off in every FPM pool"
		case on:
			s.Effective = "on"
		default:
			s.Effective = "off"
		}
		res.Settings[d] = s
	}
	return res
}

// How Evaluate reads a file.
const (
	notRead = iota
	iniFile
	poolFile
)

// classify says how Evaluate reads the file at p, an absolute path: as an ini file of
// the php.ini tree at root (php.ini first, then conf.d or php.d in name order), as an
// FPM file whose pool directives count, or not at all.
func classify(p string) (kind int, root string, order int) {
	if !configPath.MatchString(p) {
		return notRead, "", 0
	}
	base, parent := path.Base(p), path.Dir(p)
	switch {
	case strings.HasSuffix(p, ".ini"):
		if base == "php.ini" {
			return iniFile, parent, 0
		}
		if b := path.Base(parent); b == "conf.d" || b == "php.d" {
			return iniFile, path.Dir(parent), 1
		}
	case strings.HasSuffix(p, ".conf"):
		return poolFile, "", 0
	}
	return notRead, "", 0
}

// Reads reports whether Evaluate reads the file at this path: a php.ini, an .ini file
// in a conf.d or php.d directory, or an FPM .conf file, in a PHP configuration
// location.
func Reads(p string) bool {
	kind, _, _ := classify(path.Clean("/" + p))
	return kind != notRead
}

// ReadsDir reports whether Evaluate reads files directly in this directory, as it
// does in /usr/local/etc/php, /usr/local/etc/php/conf.d, /etc/php/8.3/fpm/pool.d or
// /etc/php83/conf.d.
func ReadsDir(dir string) bool {
	d := path.Clean("/" + dir)
	return Reads(path.Join(d, "x.ini")) || Reads(path.Join(d, "x.conf"))
}

// Layout is where an image's PHP reads its configuration, as far as the image's own
// files show it. PHP reads php.ini from, and scans for .ini files in, directories
// compiled into it, which no file read out of the image names; only directories that
// already hold the image's own files are known to be those. Evaluate reads every php.ini
// and conf.d or php.d file in a PHP configuration location, so a file added at run time
// (by a Kubernetes mount, say) counts only when Layout.Reads says PHP reads it too.
type Layout struct {
	roots    map[string]bool // directories of php.ini trees: /usr/local/etc/php, /etc/php/8.3/fpm
	scanDirs map[string]bool // conf.d and php.d directories with the image's own .ini files
	confDirs map[string]bool // directories with the image's own FPM pool files
	conf     map[string]bool // the image's own FPM .conf files
}

// NewLayout reads the layout from an image's configuration files, by path.
func NewLayout(files map[string]string) Layout {
	l := Layout{roots: map[string]bool{}, scanDirs: map[string]bool{}, confDirs: map[string]bool{}, conf: map[string]bool{}}
	for name := range files {
		p := path.Clean("/" + name)
		switch kind, root, order := classify(p); kind {
		case iniFile:
			l.roots[root] = true
			if order > 0 {
				l.scanDirs[path.Dir(p)] = true
			}
		case poolFile:
			l.conf[p] = true
			// php-fpm.conf includes the pool files; its own directory isn't one of them.
			if path.Base(p) != "php-fpm.conf" {
				l.confDirs[path.Dir(p)] = true
			}
		}
	}
	return l
}

// PHPIni reports whether p, an absolute path, is where the image's PHP reads php.ini
// anyway: the php.ini of one of its php.ini trees, or the tree's directory, as PHP's
// -c can name either.
func (l Layout) PHPIni(p string) bool {
	if !path.IsAbs(p) {
		return false
	}
	p = path.Clean(p)
	return l.roots[p] || path.Base(p) == "php.ini" && l.roots[path.Dir(p)]
}

// FPMConfig reports whether p, an absolute path, is one of the image's own
// php-fpm.conf files.
func (l Layout) FPMConfig(p string) bool {
	if !path.IsAbs(p) {
		return false
	}
	p = path.Clean(p)
	return path.Base(p) == "php-fpm.conf" && l.conf[p]
}

// Reads reports whether the image's PHP reads a configuration file at p: the php.ini
// of one of its php.ini trees, an .ini file in a scan directory that holds its own .ini
// files, or an FPM .conf file that is one of its own or sits next to its pool files.
func (l Layout) Reads(p string) bool {
	p = path.Clean("/" + p)
	switch kind, root, order := classify(p); kind {
	case iniFile:
		if order == 0 {
			return l.roots[root]
		}
		return l.scanDirs[path.Dir(p)]
	case poolFile:
		return l.conf[p] || l.confDirs[path.Dir(p)]
	}
	return false
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

// Switch reads a value of a boolean setting as Evaluate does: on, or off, or ok false
// for a value that is neither, such as one from an environment variable.
func Switch(v string) (on, ok bool) {
	b := parseBool(v)
	if b == nil {
		return false, false
	}
	return *b, true
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
