package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/yusufyildiz34/whichphp/internal/phpini"
)

// ConfigMapReader returns "kubectl get configmap <name> -n <namespace> -o json"
// output. Its error wraps ErrNotFound when the ConfigMap doesn't exist.
type ConfigMapReader func(ctx context.Context, namespace, name string) ([]byte, error)

// DockerInspector returns "docker image inspect" output for an image ID or a
// repo@sha256:... reference. Its error wraps ErrNotFound when the daemon has no such
// image.
type DockerInspector func(ctx context.Context, ref string) ([]byte, error)

// ErrNotFound is what a reader's error wraps when the object doesn't exist.
var ErrNotFound = errors.New("not found")

// containerSpec is what the pod spec says about where a container's PHP reads its
// settings from.
type containerSpec struct {
	Mounts []mountSpec `json:"mounts,omitempty"`
	// IniEnv are PHPRC and PHP_INI_SCAN_DIR, when the env list sets them: they move
	// where PHP looks for its ini files.
	IniEnv []envSetting `json:"iniEnv,omitempty"`
	// EnvFrom are the ConfigMaps and Secrets whose keys become variables, which can
	// set PHPRC and PHP_INI_SCAN_DIR too.
	EnvFrom []envSource `json:"envFrom,omitempty"`
	// Command is what the container's command line says about PHP's settings.
	Command cmdLine `json:"command,omitempty"`
}

// envSource is an envFrom entry.
type envSource struct {
	Kind     string `json:"kind"` // configMap or secret
	Name     string `json:"name"`
	Prefix   string `json:"prefix,omitempty"`
	Optional bool   `json:"optional,omitempty"`
}

// cmdLine is what a container's command and args say about PHP's settings.
type cmdLine struct {
	// Flags are PHP's options that change which ini files it reads, or set
	// session.upload_progress.enabled.
	Flags []cmdFlag `json:"flags,omitempty"`
	// Upload is session.upload_progress.enabled as the last -d for it sets it: "on",
	// "off", "unknown" for a value that is neither, or "" without one.
	Upload string `json:"upload,omitempty"`
	// Env are PHPRC and PHP_INI_SCAN_DIR as the command line sets them, in a shell
	// script or with env.
	Env []envSetting `json:"env,omitempty"`
}

// cmdFlag is one of PHP's options: its letter (c, d, n, p or y, for the long forms
// too), the path it names, if any, and its text as written.
type cmdFlag struct {
	Option string `json:"option"`
	Path   string `json:"path,omitempty"`
	Text   string `json:"text"`
}

// shellRE matches the name of a shell, whose -c takes a script.
var shellRE = regexp.MustCompile(`^(sh|bash|dash|ash|zsh)$`)

// phpProgramRE matches the name of a PHP program whose options whichphp reads: php,
// php-fpm or php-cgi, with or without the PHP version (php8.3, php-fpm83).
var phpProgramRE = regexp.MustCompile(`^php(-fpm|-cgi)?[0-9.]*$`)

// iniVarRE matches a shell word that sets PHPRC or PHP_INI_SCAN_DIR: an assignment
// before a command, or after export or env.
var iniVarRE = regexp.MustCompile(`^(PHPRC|PHP_INI_SCAN_DIR)=(.*)$`)

// phpLongWithArg are the long options of php, php-fpm and php-cgi that take an
// argument, as the next word or after "=".
var phpLongWithArg = map[string]bool{
	"php-ini": true, "define": true, "fpm-config": true, "prefix": true, "pid": true, "file": true, "run": true,
	"zend-extension": true, "process-begin": true, "process-code": true, "process-file": true, "process-end": true,
	"docroot": true, "server": true, "rf": true, "rfunction": true, "rc": true, "rclass": true, "re": true,
	"rextension": true, "rz": true, "rzendextension": true, "ri": true, "rextinfo": true,
}

// phpShortOptions returns, for a PHP program, its short options that take an argument,
// and those whose argument is the script, after which the script's own arguments
// follow.
func phpShortOptions(program string) (withArg, script string) {
	switch {
	case strings.Contains(program, "fpm"):
		return "cdgpy", ""
	case strings.Contains(program, "cgi"):
		return "bcdfTz", "f"
	}
	return "BcdEFfRrStz", "fr"
}

// word is a word of a command line, or a shell's command separator.
type word struct {
	text string
	sep  bool
}

// shellWords splits a shell script into words and separators (;, &, |, &&, || and
// newlines). Quotes are dropped, so a quoted word may come apart; that only loses
// options whichphp looks for.
func shellWords(s string) []word {
	var out []word
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			out = append(out, word{text: b.String()})
			b.Reset()
		}
	}
	for _, r := range s {
		switch r {
		case ' ', '\t', '\r':
			flush()
		case '\n', ';', '&', '|':
			flush()
			if len(out) == 0 || !out[len(out)-1].sep {
				out = append(out, word{sep: true})
			}
		case '"', '\'':
		default:
			b.WriteRune(r)
		}
	}
	flush()
	return out
}

// cmdLineOf reads what a container's command and args, and the script a shell's -c
// takes there ("sh -c 'php-fpm -n'"), say about PHP's settings. Any other argument is
// one word, spaces and all, as the kubelet passes it. PHP's options are read only as
// options of a php, php-fpm or php-cgi program: after its name, before its script and
// before the next command, so "php artisan queue:work -n" and supervisord's -c don't
// count. A word that sets PHPRC or PHP_INI_SCAN_DIR counts anywhere.
func cmdLineOf(command, args []string) cmdLine {
	var words []word
	// shell is set after a shell's name, and script once one of its options is -c:
	// its first argument that isn't an option is then the script.
	shell, script := false, false
	for _, a := range append(append([]string(nil), command...), args...) {
		option := strings.HasPrefix(a, "-") && a != "-" && a != "--"
		switch {
		case shell && option:
			script = script || !strings.HasPrefix(a, "--") && strings.ContainsRune(a[1:], 'c')
		case shell && script:
			// The script's commands stand apart from the words around it.
			words = append(words, word{sep: true})
			words = append(words, shellWords(a)...)
			words = append(words, word{sep: true})
			shell, script = false, false
			continue
		default:
			shell, script = shellRE.MatchString(path.Base(a)), false
		}
		words = append(words, word{text: a})
	}
	var out cmdLine
	flag := func(option, file, text string) {
		if len(text) > 120 {
			text = text[:120] + "…"
		}
		out.Flags = append(out.Flags, cmdFlag{Option: option, Path: file, Text: text})
	}
	define := func(d string) {
		name, value, hasValue := strings.Cut(d, "=")
		if !strings.EqualFold(strings.TrimSpace(name), phpini.UploadProgress) {
			return
		}
		flag("d", "", "-d "+d)
		if !hasValue {
			value = "1" // -d name alone sets it to 1
		}
		switch on, ok := phpini.Switch(value); {
		// PHP quotes a value that starts with a space, which then reads as neither.
		case !ok, value != strings.TrimSpace(value):
			out.Upload = "unknown"
		case on:
			out.Upload = "on"
		default:
			out.Upload = "off"
		}
	}
	inPHP, fpm := false, false
	withArg, scriptOption := "", ""
	for i := 0; i < len(words); i++ {
		w := words[i]
		// The next word, as an option's argument; a separator ends the command first.
		next := func() string {
			if i+1 < len(words) && !words[i+1].sep {
				i++
				return words[i].text
			}
			return ""
		}
		switch {
		case w.sep:
			inPHP = false
			continue
		case iniVarRE.MatchString(w.text):
			m := iniVarRE.FindStringSubmatch(w.text)
			out.Env = append(out.Env, envSetting{Name: m[1], Value: m[2], Known: !strings.ContainsAny(m[2], "$`")})
			continue
		case !inPHP:
			if base := path.Base(w.text); phpProgramRE.MatchString(base) {
				inPHP, fpm = true, strings.Contains(base, "fpm")
				withArg, scriptOption = phpShortOptions(base)
			}
			continue
		case w.text == "--" || !strings.HasPrefix(w.text, "-") || w.text == "-":
			// The script, or what follows it: no more of PHP's options. The word may
			// name another program.
			inPHP = false
			if w.text != "--" {
				i--
			}
			continue
		}
		if long, ok := strings.CutPrefix(w.text, "--"); ok {
			name, value, hasValue := strings.Cut(long, "=")
			if phpLongWithArg[name] && !hasValue {
				value = next()
			}
			text := w.text
			if !hasValue && value != "" {
				text += " " + value
			}
			switch {
			case name == "define":
				define(value)
			case name == "php-ini":
				flag("c", value, text)
			case name == "no-php-ini":
				flag("n", "", text)
			case name == "fpm-config" && fpm:
				flag("y", value, text)
			case name == "prefix" && fpm:
				flag("p", value, text)
			case name == "file", name == "run":
				inPHP = false
			}
			continue
		}
		// Short options, alone or grouped (-Fn); one that takes an argument takes the
		// rest of the word (-dname=value), or else the next word.
		text := w.text
		for j := 1; j < len(w.text); j++ {
			letter := w.text[j]
			if strings.IndexByte(withArg, letter) < 0 {
				if letter == 'n' {
					flag("n", "", text)
				}
				continue
			}
			value := w.text[j+1:]
			if value == "" {
				value = next()
				text += " " + value
			}
			switch letter {
			case 'd':
				define(value)
			case 'c':
				flag("c", value, text)
			case 'y', 'p':
				// Only php-fpm takes them: its configuration file, and the prefix it
				// finds that file and its pools under.
				flag(string(letter), value, text)
			}
			if strings.IndexByte(scriptOption, letter) >= 0 {
				inPHP = false
			}
			break
		}
	}
	return out
}

type mountSpec struct {
	MountPath string `json:"mountPath"`
	SubPath   string `json:"subPath,omitempty"`
	// SubPathExpr is kept when it uses a variable whose value the pod spec doesn't
	// say, so the path inside the volume isn't known.
	SubPathExpr string     `json:"subPathExpr,omitempty"`
	Volume      volumeSpec `json:"volume"`
}

// volumeSpec is a pod volume's source. Only ConfigMaps are read; of any other source
// whichphp keeps the kind (secret, projected, emptyDir, ...) to say what it didn't read.
type volumeSpec struct {
	Kind     string      `json:"kind"`
	Name     string      `json:"name,omitempty"` // the ConfigMap's
	Items    []keyToPath `json:"items,omitempty"`
	Optional bool        `json:"optional,omitempty"`
}

type keyToPath struct {
	Key  string `json:"key"`
	Path string `json:"path"`
}

type envSetting struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
	Known bool   `json:"known"`
}

// ConfigMount is a ConfigMap mounted at a PHP configuration path.
type ConfigMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	SubPath   string `json:"subPath,omitempty"`
	// Files are the mounted files PHP reads as configuration.
	Files []string `json:"files,omitempty"`
	// LeftOut are the mounted files outside the places the image's PHP reads its
	// configuration from, which were left out.
	LeftOut []string `json:"leftOut,omitempty"`
	// Missing is set for an optional ConfigMap that doesn't exist, which Kubernetes
	// mounts as an empty directory.
	Missing bool `json:"missing,omitempty"`
	// Error says why the ConfigMap couldn't be read; the image's files were kept.
	Error string `json:"error,omitempty"`
}

// volumeSpecs reads a pod's volumes, by name.
func volumeSpecs(raw []map[string]json.RawMessage) map[string]volumeSpec {
	out := map[string]volumeSpec{}
	for _, v := range raw {
		var name string
		if json.Unmarshal(v["name"], &name) != nil || name == "" {
			continue
		}
		var kinds []string
		for k := range v {
			if k != "name" {
				kinds = append(kinds, k)
			}
		}
		sort.Strings(kinds)
		var s volumeSpec
		if len(kinds) > 0 {
			s.Kind = kinds[0]
		}
		if b, ok := v["configMap"]; ok {
			var cm struct {
				Name     string      `json:"name"`
				Items    []keyToPath `json:"items"`
				Optional *bool       `json:"optional"`
			}
			s.Kind = "configMap"
			if json.Unmarshal(b, &cm) == nil {
				s.Name, s.Items, s.Optional = cm.Name, cm.Items, cm.Optional != nil && *cm.Optional
			}
		}
		out[name] = s
	}
	return out
}

// specOf reads a container's mounts and the variables that move PHP's ini files.
func specOf(c podContainer, volumes map[string]volumeSpec) containerSpec {
	env := newEnvironment(c)
	var s containerSpec
	for _, m := range c.VolumeMounts {
		v, ok := volumes[m.Name]
		if !ok || m.MountPath == "" {
			continue
		}
		ms := mountSpec{MountPath: m.MountPath, SubPath: m.SubPath, Volume: v}
		if m.SubPathExpr != "" {
			// The kubelet expands $(VAR) in it with the container's variables.
			if sub, ok := env.expand(m.SubPathExpr, true); ok {
				ms.SubPath = sub
			} else {
				ms.SubPath, ms.SubPathExpr = "", m.SubPathExpr
			}
		}
		s.Mounts = append(s.Mounts, ms)
	}
	for _, name := range iniVars {
		if value, known, set := env.get(name); set {
			s.IniEnv = append(s.IniEnv, envSetting{Name: name, Value: value, Known: known})
		}
	}
	for _, e := range c.EnvFrom {
		switch {
		case e.ConfigMapRef != nil:
			s.EnvFrom = append(s.EnvFrom, envSource{Kind: "configMap", Name: e.ConfigMapRef.Name, Prefix: e.Prefix,
				Optional: e.ConfigMapRef.Optional != nil && *e.ConfigMapRef.Optional})
		case e.SecretRef != nil:
			s.EnvFrom = append(s.EnvFrom, envSource{Kind: "secret", Name: e.SecretRef.Name, Prefix: e.Prefix})
		default:
			s.EnvFrom = append(s.EnvFrom, envSource{Prefix: e.Prefix})
		}
	}
	s.Command = cmdLineOf(c.Command, c.Args)
	return s
}

// iniVars are the variables that move where PHP reads its ini files.
var iniVars = []string{"PHPRC", "PHP_INI_SCAN_DIR"}

// iniVarEffect says what a variable of iniVars does.
func iniVarEffect(name string) string {
	if name == "PHP_INI_SCAN_DIR" {
		return "PHP may read .ini files"
	}
	return "PHP may read its php.ini"
}

// environment is a container's variables as the kubelet sets them from its env
// list: a later entry wins, and $(VAR) in a value refers to an earlier one ($$ is a
// literal $). Variables from a ConfigMap, Secret or field (valueFrom) are set, but to
// values the pod spec doesn't say; envFrom can set any variable, whose values aren't
// read here (applyConfig reads its ConfigMaps for PHPRC and PHP_INI_SCAN_DIR).
type environment struct {
	values  map[string]string
	unknown map[string]bool
	envFrom bool
}

func newEnvironment(c podContainer) environment {
	e := environment{values: map[string]string{}, unknown: map[string]bool{}, envFrom: len(c.EnvFrom) > 0}
	for _, v := range c.Env {
		if v.Name == "" {
			continue
		}
		value, known := "", len(v.ValueFrom) == 0 || string(v.ValueFrom) == "null"
		if known {
			value, known = e.expand(v.Value, false)
		}
		if known {
			e.values[v.Name] = value
			delete(e.unknown, v.Name)
		} else {
			delete(e.values, v.Name)
			e.unknown[v.Name] = true
		}
	}
	return e
}

// get returns a variable's value, whether that value is known, and whether the env
// list sets the variable at all.
func (e environment) get(name string) (value string, known, set bool) {
	if v, ok := e.values[name]; ok {
		return v, true, true
	}
	return "", false, e.unknown[name]
}

// expand replaces $(VAR) references as the kubelet does. A reference to a variable
// that isn't set stays as written in an env value, but stops a pod from starting in
// a subPathExpr (strict), so there it must have come from somewhere unseen. ok is
// false when the result depends on a value the pod spec doesn't say.
func (e environment) expand(s string, strict bool) (string, bool) {
	var b strings.Builder
	ok := true
	for i := 0; i < len(s); i++ {
		if s[i] != '$' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch s[i+1] {
		case '$':
			b.WriteByte('$')
			i++
		case '(':
			end := strings.IndexByte(s[i+2:], ')')
			if end < 0 {
				b.WriteString("$(")
				i++
				continue
			}
			name := s[i+2 : i+2+end]
			i += 2 + end
			if v, known := e.values[name]; known {
				b.WriteString(v)
			} else if e.unknown[name] || e.envFrom || strict {
				ok = false
			} else {
				b.WriteString("$(" + name + ")")
			}
		default:
			b.WriteString(s[i : i+2])
			i++
		}
	}
	return b.String(), ok
}

// ParseConfigMap reads "kubectl get configmap -o json" output: the ConfigMap's
// data and binaryData, by key.
func ParseConfigMap(b []byte) (map[string]string, error) {
	var cm struct {
		Kind       string            `json:"kind"`
		Data       map[string]string `json:"data"`
		BinaryData map[string][]byte `json:"binaryData"`
	}
	if err := json.Unmarshal(b, &cm); err != nil {
		return nil, fmt.Errorf("reading the ConfigMap: %w", err)
	}
	if cm.Kind != "ConfigMap" {
		return nil, errors.New("kubectl's output isn't a ConfigMap")
	}
	out := map[string]string{}
	for k, v := range cm.BinaryData {
		out[k] = string(v)
	}
	// The API server refuses a key in both; should one appear, the text wins, as it
	// does for a mount that lists its items.
	for k, v := range cm.Data {
		out[k] = v
	}
	return out, nil
}

var (
	dnsLabelRE     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	dnsSubdomainRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
	configKeyRE    = regexp.MustCompile(`^[-._a-zA-Z0-9]+$`)
)

type configMapData struct {
	data    map[string]string
	missing bool
	err     error
}

// configMaps reads each ConfigMap once per check.
type configMaps struct {
	read  ConfigMapReader
	cache map[string]configMapData
}

func (c *configMaps) get(ctx context.Context, namespace, name string) configMapData {
	key := namespace + "/" + name
	if d, ok := c.cache[key]; ok {
		return d
	}
	var d configMapData
	switch {
	// Names go to kubectl as arguments, so they must be what the API allows.
	case !dnsLabelRE.MatchString(namespace) || len(name) > 253 || !dnsSubdomainRE.MatchString(name):
		d.err = errors.New("not a valid ConfigMap name")
	case c.read == nil:
		d.err = errors.New("ConfigMaps weren't read")
	default:
		b, err := c.read(ctx, namespace, name)
		switch {
		case errors.Is(err, ErrNotFound):
			d.missing = true
		case err != nil:
			d.err = err
		default:
			d.data, d.err = ParseConfigMap(b)
		}
	}
	c.cache[key] = d
	return d
}

// volumeFiles returns the files a ConfigMap volume holds, by path inside the volume,
// as the kubelet writes them: every key, or only the listed items at their paths. A
// missing optional ConfigMap, or key, leaves nothing.
func volumeFiles(v volumeSpec, d configMapData) (map[string]string, error) {
	switch {
	case d.err != nil:
		return nil, d.err
	case d.missing && !v.Optional:
		// The pod started with it, so it was deleted since; the kubelet keeps the
		// files it last wrote, which can't be known now.
		return nil, errors.New("it doesn't exist any more")
	}
	files := map[string]string{}
	if len(v.Items) == 0 {
		for k, content := range d.data {
			if configKeyRE.MatchString(k) && !strings.HasPrefix(k, "..") && k != "." {
				files[k] = content
			}
		}
		return files, nil
	}
	for _, it := range v.Items {
		rel, ok := cleanRel(it.Path)
		if !ok || rel == "" {
			continue
		}
		content, found := d.data[it.Key]
		if !found {
			if v.Optional || d.missing {
				continue
			}
			return nil, fmt.Errorf("it has no key %s", it.Key)
		}
		files[rel] = content
	}
	return files, nil
}

// cleanRel cleans a path inside a volume as Kubernetes allows it: relative, with no
// ".." element and not starting with "..". ok is false for anything else.
func cleanRel(p string) (string, bool) {
	if p == "" {
		return "", true
	}
	if path.IsAbs(p) {
		return "", false
	}
	for _, e := range strings.Split(p, "/") {
		if e == ".." {
			return "", false
		}
	}
	c := path.Clean(p)
	if c == "." {
		return "", true
	}
	if strings.HasPrefix(c, "..") {
		return "", false
	}
	return c, true
}

// under reports whether p is dir or inside it.
func under(p, dir string) bool {
	return dir == "/" || p == dir || strings.HasPrefix(p, dir+"/")
}

// mounted places a volume's files in the container: all of them under the mount
// path, or, with a subPath, the one file at the mount path or the directory's files
// under it. A subPath the volume doesn't have becomes an empty directory.
func mounted(files map[string]string, target, sub string) map[string]string {
	out := map[string]string{}
	if sub == "" {
		for rel, content := range files {
			out[path.Join(target, rel)] = content
		}
		return out
	}
	if content, ok := files[sub]; ok {
		out[target] = content
		return out
	}
	for rel, content := range files {
		if strings.HasPrefix(rel, sub+"/") {
			out[path.Join(target, rel[len(sub)+1:])] = content
		}
	}
	return out
}

// relevant reports whether a mount can change what PHP reads: it covers configuration
// files that are already there, or it puts files where PHP reads them.
func relevant(m mountSpec, target, sub string, files map[string]string) bool {
	for p := range files {
		if under(p, target) && phpini.Reads(p) {
			return true
		}
	}
	if phpini.Reads(target) || phpini.ReadsDir(target) {
		return true
	}
	for _, it := range m.Volume.Items {
		rel, ok := cleanRel(it.Path)
		if !ok || rel == "" {
			continue
		}
		p := ""
		switch {
		case sub == "":
			p = path.Join(target, rel)
		case rel == sub:
			p = target
		case strings.HasPrefix(rel, sub+"/"):
			p = path.Join(target, rel[len(sub)+1:])
		}
		if p != "" && phpini.Reads(p) {
			return true
		}
	}
	return false
}

// applyConfig works out session.upload_progress.enabled for a container as its PHP
// sees it: the image's configuration files, with the ConfigMaps the pod mounts at
// PHP configuration paths laid over them as Kubernetes mounts them. A mounted file
// replaces the image's file at its path, and a mounted directory hides the image's
// directory.
//
// "off" is reported only when everything that can change it was read. A file from a
// ConfigMap counts only where the image's own PHP reads its configuration (see
// phpini.Layout); one elsewhere, which PHP may or may not read, makes the setting
// unknown when it would change it. A mount that can't be read, and PHPRC or
// PHP_INI_SCAN_DIR in the env list, are left out with a note, and make "off" unknown,
// since they could turn it back on; "on" stays.
func (c *configMaps) applyConfig(ctx context.Context, cr *ContainerResult) {
	r := cr.Result
	cr.UploadProgress = r.UploadProgress
	if r.UploadProgress == "" || r.files == nil {
		return
	}
	files := map[string]string{}
	for p, content := range r.files {
		files[path.Clean("/"+p)] = content
	}
	layout := phpini.NewLayout(files)
	// unread is set when something whichphp didn't read may change the setting; stray
	// holds the ConfigMap files outside the places PHP reads, by path, with the name of
	// their ConfigMap.
	unread := len(cr.spec.IniEnv) > 0
	stray := map[string]string{}
	// Container runtimes mount parents before what is inside them.
	mounts := append([]mountSpec(nil), cr.spec.Mounts...)
	sort.SliceStable(mounts, func(i, j int) bool {
		return depth(mounts[i].MountPath) < depth(mounts[j].MountPath)
	})
	for _, m := range mounts {
		target := path.Clean("/" + m.MountPath)
		sub, ok := cleanRel(m.SubPath)
		if !ok || !relevant(m, target, sub, files) {
			continue
		}
		switch {
		case m.SubPathExpr != "":
			unread = true
			cr.Notes = append(cr.Notes, fmt.Sprintf("The volume at %s is mounted with a subPathExpr that uses variables the pod spec doesn't set, so it was left out; the setting may differ.", target))
			continue
		case m.Volume.Kind != "configMap":
			unread = true
			cr.Notes = append(cr.Notes, fmt.Sprintf("%s is mounted at %s, which whichphp doesn't read, so it was left out; the setting may differ.", volumeLabel(m.Volume.Kind), target))
			continue
		}
		cm := ConfigMount{Name: m.Volume.Name, MountPath: target, SubPath: sub}
		d := c.get(ctx, cr.Namespace, m.Volume.Name)
		in, err := volumeFiles(m.Volume, d)
		if err != nil {
			unread = true
			cm.Error = oneLine(err.Error())
			cr.ConfigMaps = append(cr.ConfigMaps, cm)
			cr.Notes = append(cr.Notes, fmt.Sprintf("ConfigMap %s, mounted at %s, couldn't be read (%s), so it was left out; the setting may differ.", m.Volume.Name, target, cm.Error))
			continue
		}
		cm.Missing = d.missing
		for p := range files {
			if under(p, target) {
				delete(files, p)
			}
		}
		for p := range stray {
			if under(p, target) {
				delete(stray, p)
			}
		}
		for p, content := range mounted(in, target, sub) {
			files[p] = content
			switch {
			case !phpini.Reads(p):
			case layout.Reads(p):
				cm.Files = append(cm.Files, p)
			default:
				stray[p] = m.Volume.Name
				cm.LeftOut = append(cm.LeftOut, p)
			}
		}
		sort.Strings(cm.Files)
		sort.Strings(cm.LeftOut)
		cr.ConfigMaps = append(cr.ConfigMaps, cm)
	}

	// The setting without the stray files, and, to see whether they matter, with them.
	read := make(map[string]string, len(files))
	for p, content := range files {
		if _, ok := stray[p]; !ok {
			read[p] = content
		}
	}
	s := phpini.Evaluate(read, true).Settings[phpini.UploadProgress]
	cr.UploadProgress, cr.UploadProgressSetIn = s.Effective, s.SetIn
	if len(stray) > 0 {
		matters := phpini.Evaluate(files, true).Settings[phpini.UploadProgress].Effective != s.Effective
		paths := make([]string, 0, len(stray))
		for p := range stray {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			n := fmt.Sprintf("ConfigMap %s puts %s outside the places this image's PHP reads its configuration from, so it was left out", stray[p], p)
			if matters {
				n += "; PHP may still read it, and it would change the setting, so the setting is unknown"
			}
			cr.Notes = append(cr.Notes, n+".")
		}
		if matters {
			cr.UploadProgress, cr.UploadProgressSetIn = "unknown", nil
		}
	}
	inEnv := map[string]bool{}
	for _, v := range cr.spec.IniEnv {
		inEnv[v.Name] = true
		value := ", from a source the pod spec doesn't show"
		if v.Known {
			value = fmt.Sprintf(" to %q", v.Value)
		}
		cr.Notes = append(cr.Notes, fmt.Sprintf("%s is set%s, so %s from a place whichphp doesn't follow; the setting may differ.", v.Name, value, iniVarEffect(v.Name)))
	}
	if c.envFrom(ctx, cr, inEnv) {
		unread = true
	}
	for _, v := range cr.spec.Command.Env {
		unread = true
		value := ", to a value the pod spec doesn't show,"
		if v.Known {
			value = fmt.Sprintf(" to %q", v.Value)
		}
		cr.Notes = append(cr.Notes, fmt.Sprintf("%s is set%s in the container's command line, so %s from a place whichphp doesn't follow; the setting may differ.", v.Name, value, iniVarEffect(v.Name)))
	}
	// What wasn't read may turn the setting back on.
	if unread && (cr.UploadProgress == "off" || cr.UploadProgress == "off-in-fpm-pool") {
		cr.UploadProgress, cr.UploadProgressSetIn = "unknown", nil
	}
	// PHP's options win over its files: -d can set the setting itself, and -c, -n and
	// FPM's -y and -p change which files are read. -c and -y naming the image's own
	// php.ini or php-fpm.conf change nothing. Only a -d that turns it on says what the
	// setting is.
	var flags []string
	for _, f := range cr.spec.Command.Flags {
		if f.Option == "c" && layout.PHPIni(f.Path) || f.Option == "y" && layout.FPMConfig(f.Path) {
			continue
		}
		flags = append(flags, f.Text)
	}
	if cl := cr.spec.Command; len(flags) > 0 {
		flags := strings.Join(flags, ", ")
		if cl.Upload == "on" {
			cr.UploadProgress, cr.UploadProgressSetIn = "on", nil
			cr.Notes = append(cr.Notes, fmt.Sprintf("The container's command line passes %s to PHP, which turns the setting on, whatever the files say.", flags))
		} else {
			cr.UploadProgress, cr.UploadProgressSetIn = "unknown", nil
			cr.Notes = append(cr.Notes, fmt.Sprintf("The container's command line passes %s to PHP, which can change the setting, so it is unknown.", flags))
		}
	}
}

// envFrom notes the envFrom sources that set, or may set, PHPRC or PHP_INI_SCAN_DIR,
// which whichphp doesn't follow, and reports whether there is one. A ConfigMap is read
// to see whether it does; a Secret never is. A variable the env list sets (inEnv) wins
// over envFrom.
func (c *configMaps) envFrom(ctx context.Context, cr *ContainerResult, inEnv map[string]bool) bool {
	if inEnv["PHPRC"] && inEnv["PHP_INI_SCAN_DIR"] {
		return false
	}
	found := false
	note := func(format string, a ...any) {
		found = true
		cr.Notes = append(cr.Notes, fmt.Sprintf(format, a...))
	}
	for _, src := range cr.spec.EnvFrom {
		switch src.Kind {
		case "configMap":
			d := c.get(ctx, cr.Namespace, src.Name)
			switch {
			case d.err != nil:
				note("ConfigMap %s, whose keys the container gets as variables (envFrom), couldn't be read (%s); it may set PHPRC or PHP_INI_SCAN_DIR, so the setting may differ.", src.Name, oneLine(d.err.Error()))
			case d.missing && !src.Optional:
				note("ConfigMap %s, whose keys the container gets as variables (envFrom), doesn't exist any more; it may have set PHPRC or PHP_INI_SCAN_DIR when the pod started, so the setting may differ.", src.Name)
			}
			for _, name := range iniVars {
				if inEnv[name] || !strings.HasPrefix(name, src.Prefix) {
					continue
				}
				if value, ok := d.data[name[len(src.Prefix):]]; ok {
					note("%s is set to %q by ConfigMap %s (envFrom), so %s from a place whichphp doesn't follow; the setting may differ.", name, value, src.Name, iniVarEffect(name))
				}
			}
		case "secret":
			note("Secret %s, whose keys the container gets as variables (envFrom), isn't read; it may set PHPRC or PHP_INI_SCAN_DIR, so the setting may differ.", src.Name)
		default:
			note("An envFrom source whichphp doesn't read may set PHPRC or PHP_INI_SCAN_DIR, so the setting may differ.")
		}
	}
	return found
}

func depth(p string) int {
	return strings.Count(path.Clean("/"+p), "/")
}

// volumeLabel names a volume kind in a sentence.
func volumeLabel(kind string) string {
	switch kind {
	case "secret":
		return "A Secret"
	case "":
		return "A volume"
	}
	if strings.ContainsRune("aeiouAEIOU", rune(kind[0])) {
		return "An " + kind + " volume"
	}
	return "A " + kind + " volume"
}

// MatchDockerImage reads "docker image inspect" output and returns the ID and
// platform of the image a container runs: the one whose ID, or one of whose repo
// digests, is the runtime's image ID (local) or the running digest. id is "" when
// none is.
func MatchDockerImage(b []byte, running, local string) (id, platform string, err error) {
	var imgs []struct {
		ID           string   `json:"Id"`
		RepoDigests  []string `json:"RepoDigests"`
		Os           string   `json:"Os"`
		Architecture string   `json:"Architecture"`
	}
	if err := json.Unmarshal(b, &imgs); err != nil {
		return "", "", fmt.Errorf("reading docker image inspect output: %w", err)
	}
	want := local
	if want == "" {
		want = Digest(running)
	}
	if want == "" {
		return "", "", nil
	}
	for _, img := range imgs {
		// The ID becomes a Syft source, so it must be exactly an image ID.
		if !strings.HasPrefix(img.ID, "sha256:") || !localIDRE.MatchString(img.ID) {
			continue
		}
		match := img.ID == want
		for _, rd := range img.RepoDigests {
			match = match || Digest(rd) == want
		}
		if match {
			if img.Os != "" && img.Architecture != "" {
				platform = img.Os + "/" + img.Architecture
			}
			return img.ID, platform, nil
		}
	}
	return "", "", nil
}
