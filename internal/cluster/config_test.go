package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yusufyildiz34/whichphp/internal/phpini"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

type m = map[string]any

// fpmFiles are the configuration files of a php:8.4-fpm image whose builder turned
// upload progress off in conf.d.
var fpmFiles = map[string]string{
	"/usr/local/etc/php/conf.d/docker-php-ext-sodium.ini": "extension=sodium\n",
	"/usr/local/etc/php/conf.d/zz-off.ini":                "session.upload_progress.enabled = Off\n",
	"/usr/local/etc/php-fpm.conf":                         "[global]\ninclude=etc/php-fpm.d/*.conf\n",
	"/usr/local/etc/php-fpm.d/www.conf":                   "[www]\nuser = www-data\n",
}

// withFiles is the scan result for an image with these configuration files.
func withFiles(action verdict.Action, version string, v verdict.Verdict, files map[string]string) verdict.Report {
	r := rep(action, version, v)
	r.ConfigFiles = files
	if version != "" {
		r.Settings = phpini.Evaluate(files, true).Settings
	}
	return r
}

// configPod is a running bare pod whose container "php" runs php@sha256:aaa... with
// these mounts, volumes and variables.
func configPod(ns, name string, mounts, volumes, env []m) m {
	c := m{"name": "php", "image": "php:8.4-fpm", "volumeMounts": mounts, "env": env}
	return m{
		"metadata": m{"namespace": ns, "name": name},
		"spec":     m{"containers": []m{c}, "volumes": volumes},
		"status":   m{"phase": "Running", "containerStatuses": []m{{"name": "php", "imageID": "docker.io/library/php@" + d('a')}}},
	}
}

func cmJSON(data map[string]string) string {
	b, _ := json.Marshal(m{"apiVersion": "v1", "kind": "ConfigMap", "data": data})
	return string(b)
}

func cmVolume(name, configMap string, extra m) m {
	src := m{"name": configMap}
	for k, v := range extra {
		src[k] = v
	}
	return m{"name": name, "configMap": src}
}

// The service account token every pod gets; it must neither be read nor be noted.
var tokenMount, tokenVolume = m{"name": "kube-api-access-x7k2p", "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"},
	m{"name": "kube-api-access-x7k2p", "projected": m{"sources": []m{{"serviceAccountToken": m{"path": "token"}}, {"configMap": m{"name": "kube-root-ca.crt"}}}}}

// checkConfig runs a check of these pods, whose image has files, with ConfigMaps
// given as JSON by namespace/name, and returns each namespace's container and the
// reads per ConfigMap.
func checkConfig(t *testing.T, pods []m, files map[string]string, configMaps map[string]string, errs map[string]error) (map[string]ContainerResult, map[string]int, Result) {
	t.Helper()
	b, _ := json.Marshal(m{"items": pods})
	cs, _, err := Inventory(b, nil, InventoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	reads := map[string]int{}
	read := func(_ context.Context, ns, name string) ([]byte, error) {
		reads[ns+"/"+name]++
		if err := errs[ns+"/"+name]; err != nil {
			return nil, err
		}
		data, ok := configMaps[ns+"/"+name]
		if !ok {
			return nil, fmt.Errorf("configmaps %q: %w", name, ErrNotFound)
		}
		return []byte(data), nil
	}
	scan := func(context.Context, string, string) (verdict.Report, error) {
		return withFiles(verdict.ActionNeeded, "8.4.26", verdict.Vulnerable, files), nil
	}
	res := Check(context.Background(), cs, scan, func(context.Context, string) (string, error) { return d('a'), nil }, CheckOptions{ReadConfigMap: read})
	got := map[string]ContainerResult{}
	for _, w := range res.Workloads {
		for _, c := range w.Containers {
			got[w.Namespace+"/"+w.Name] = c
		}
	}
	return got, reads, res
}

func TestConfigMaps(t *testing.T) {
	confD := "/usr/local/etc/php/conf.d"
	pods := []m{
		// A file from a ConfigMap, through subPath, turns it back on.
		configPod("a", "file", []m{{"name": "ini", "mountPath": confD + "/zz-on.ini", "subPath": "zz-on.ini"}, tokenMount},
			[]m{cmVolume("ini", "php-ini", nil), tokenVolume}, nil),
		// A directory mount hides the image's conf.d, so its zz-off.ini is gone.
		configPod("a", "dir", []m{{"name": "ext", "mountPath": confD}}, []m{cmVolume("ext", "ext", nil)}, nil),
		// A ConfigMap that can't be read leaves the image's files, but could turn the
		// setting back on.
		configPod("a", "forbidden", []m{{"name": "ext", "mountPath": confD}}, []m{cmVolume("ext", "locked", nil)}, nil),
		// An optional ConfigMap that doesn't exist is an empty directory.
		configPod("a", "optional", []m{{"name": "ext", "mountPath": confD}}, []m{cmVolume("ext", "gone", m{"optional": true})}, nil),
		// A required one that doesn't exist was deleted after the pod started.
		configPod("a", "deleted", []m{{"name": "ext", "mountPath": confD}}, []m{cmVolume("ext", "gone", nil)}, nil),
		// Items place keys at their paths; the whole of /usr/local/etc/php is hidden.
		configPod("a", "items", []m{{"name": "etc", "mountPath": "/usr/local/etc/php"}},
			[]m{cmVolume("etc", "mitigation", m{"items": []m{{"key": "mitigation", "path": "conf.d/zz-mitigation.ini"}, {"key": "missing", "path": "conf.d/x.ini"}}, "optional": true})}, nil),
		// An FPM pool file through subPath, with conf.d emptied: on, but off in the pool.
		configPod("a", "pool", []m{{"name": "ext", "mountPath": confD}, {"name": "pool", "mountPath": "/usr/local/etc/php-fpm.d/www.conf", "subPath": "www.conf"}},
			[]m{cmVolume("ext", "ext", nil), cmVolume("pool", "pool", nil)}, nil),
		// An FPM pool file through subPath turns it back on over the image's conf.d off.
		configPod("a", "pool-on", []m{{"name": "pool", "mountPath": "/usr/local/etc/php-fpm.d/www.conf", "subPath": "www.conf"}},
			[]m{cmVolume("pool", "pool-on", nil)}, nil),
		// Mounts elsewhere aren't read.
		configPod("a", "elsewhere", []m{{"name": "site", "mountPath": "/var/www/html"}, tokenMount}, []m{cmVolume("site", "site", nil), tokenVolume}, nil),
		// Other volume kinds at a PHP path are named, not read, and so the image's off
		// is unknown.
		configPod("a", "secret", []m{{"name": "s", "mountPath": confD}}, []m{{"name": "s", "secret": m{"secretName": "php-ini"}}}, nil),
		configPod("a", "emptydir", []m{{"name": "e", "mountPath": confD}}, []m{{"name": "e", "emptyDir": m{}}}, nil),
		// Variables that move PHP's ini files are named.
		configPod("a", "scandir", nil, nil, []m{{"name": "PHP_INI_SCAN_DIR", "value": ":/etc/php-custom"}, {"name": "PHPRC", "valueFrom": m{"configMapKeyRef": m{"name": "x", "key": "y"}}}}),
		// subPathExpr is expanded with the container's variables, as the kubelet does.
		configPod("a", "expr", []m{{"name": "ini", "mountPath": confD + "/zz-on.ini", "subPathExpr": "$(INI)"}}, []m{cmVolume("ini", "php-ini", nil)},
			[]m{{"name": "NAME", "value": "zz-on"}, {"name": "INI", "value": "$(NAME).ini"}}),
		configPod("a", "expr-pod", []m{{"name": "ini", "mountPath": confD + "/zz-on.ini", "subPathExpr": "$(POD_NAME).ini"}}, []m{cmVolume("ini", "php-ini", nil)},
			[]m{{"name": "POD_NAME", "valueFrom": m{"fieldRef": m{"fieldPath": "metadata.name"}}}}),
		// A name kubectl could take for a flag is never passed to it.
		configPod("a", "invalid", []m{{"name": "ext", "mountPath": confD}}, []m{cmVolume("ext", "--raw=/api", nil)}, nil),
	}
	configMaps := map[string]string{
		"a/php-ini":    cmJSON(map[string]string{"zz-on.ini": "session.upload_progress.enabled = On\n"}),
		"a/ext":        cmJSON(map[string]string{"20-gd.ini": "extension=gd\n", "../evil.ini": "session.upload_progress.enabled = Off\n"}),
		"a/mitigation": cmJSON(map[string]string{"mitigation": "session.upload_progress.enabled=0\n"}),
		"a/pool":       cmJSON(map[string]string{"www.conf": "[www]\nphp_admin_flag[session.upload_progress.enabled] = off\n"}),
		"a/pool-on":    cmJSON(map[string]string{"www.conf": "[www]\nphp_admin_flag[session.upload_progress.enabled] = on\n"}),
		"a/site":       cmJSON(map[string]string{"php.ini": "session.upload_progress.enabled = On\n"}),
	}
	got, reads, res := checkConfig(t, pods, fpmFiles, configMaps, map[string]error{"a/locked": errors.New("forbidden")})

	for name, want := range map[string]struct {
		value, text string
		maps        int
	}{
		"file":      {"on", "on, set in ConfigMap php-ini (/usr/local/etc/php/conf.d/zz-on.ini)", 1},
		"dir":       {"on", "on, with ConfigMap ext at /usr/local/etc/php/conf.d mounted", 1},
		"forbidden": {"unknown", "unknown", 1},
		"optional":  {"on", "on, with ConfigMap gone at /usr/local/etc/php/conf.d mounted", 1},
		"deleted":   {"unknown", "unknown", 1},
		"items":     {"off", "off, set in ConfigMap mitigation (/usr/local/etc/php/conf.d/zz-mitigation.ini)", 1},
		"pool":      {"off-in-fpm-pool", "off in every FPM pool (on in php.ini/conf.d), set in ConfigMap pool (/usr/local/etc/php-fpm.d/www.conf)", 2},
		"pool-on":   {"on", "on, set in ConfigMap pool-on (/usr/local/etc/php-fpm.d/www.conf)", 1},
		"elsewhere": {"off", "off, from the image", 0},
		"secret":    {"unknown", "unknown", 0},
		"emptydir":  {"unknown", "unknown", 0},
		"scandir":   {"unknown", "unknown", 0},
		"expr":      {"on", "on, set in ConfigMap php-ini (/usr/local/etc/php/conf.d/zz-on.ini)", 1},
		"expr-pod":  {"unknown", "unknown", 0},
		"invalid":   {"unknown", "unknown", 1},
	} {
		c := got["a/"+name]
		if c.UploadProgress != want.value || uploadText(c) != want.text || len(c.ConfigMaps) != want.maps {
			t.Errorf("%s: %q, %q, ConfigMaps %+v, notes %q", name, c.UploadProgress, uploadText(c), c.ConfigMaps, c.Notes)
		}
	}
	// One read per ConfigMap, however many pods mount it; none for mounts elsewhere,
	// for the service account token, or for a name that isn't valid.
	for cm, want := range map[string]int{"a/php-ini": 1, "a/ext": 1, "a/locked": 1, "a/gone": 1, "a/mitigation": 1, "a/pool": 1, "a/pool-on": 1} {
		if reads[cm] != want {
			t.Errorf("%s read %d times, want %d", cm, reads[cm], want)
		}
	}
	if len(reads) != 7 {
		t.Errorf("reads: %v", reads)
	}
	// Keys that aren't file names are left out, as the kubelet leaves them out.
	if f := got["a/dir"].ConfigMaps[0].Files; len(f) != 1 || f[0] != "/usr/local/etc/php/conf.d/20-gd.ini" {
		t.Errorf("dir files: %q", f)
	}
	if !got["a/optional"].ConfigMaps[0].Missing || got["a/deleted"].ConfigMaps[0].Error != "it doesn't exist any more" {
		t.Errorf("optional %+v, deleted %+v", got["a/optional"].ConfigMaps, got["a/deleted"].ConfigMaps)
	}
	for name, note := range map[string]string{
		"forbidden": "ConfigMap locked, mounted at /usr/local/etc/php/conf.d, couldn't be read (forbidden), so it was left out; the setting may differ.",
		"deleted":   "ConfigMap gone, mounted at /usr/local/etc/php/conf.d, couldn't be read (it doesn't exist any more)",
		"invalid":   "ConfigMap --raw=/api, mounted at /usr/local/etc/php/conf.d, couldn't be read (not a valid ConfigMap name)",
		"secret":    "A Secret is mounted at /usr/local/etc/php/conf.d, which whichphp doesn't read, so it was left out",
		"emptydir":  "An emptyDir volume is mounted at /usr/local/etc/php/conf.d",
		"scandir":   `PHP_INI_SCAN_DIR is set to ":/etc/php-custom", so PHP may read .ini files from a place whichphp doesn't follow`,
		"expr-pod":  "mounted with a subPathExpr that uses variables the pod spec doesn't set",
	} {
		if n := strings.Join(got["a/"+name].Notes, " "); !strings.Contains(n, note) {
			t.Errorf("%s: notes %q lack %q", name, n, note)
		}
	}
	if n := strings.Join(got["a/scandir"].Notes, " "); !strings.Contains(n, "PHPRC is set, from a source the pod spec doesn't show") {
		t.Errorf("PHPRC from valueFrom: %q", n)
	}
	for _, name := range []string{"file", "dir", "elsewhere", "items"} {
		if n := got["a/"+name].Notes; len(n) != 0 {
			t.Errorf("%s: unexpected notes %q", name, n)
		}
	}
	// The table says where the value comes from, and the JSON keeps the mounts.
	var buf bytes.Buffer
	if err := Table(&buf, res); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"session.upload_progress.enabled: on, set in ConfigMap php-ini (/usr/local/etc/php/conf.d/zz-on.ini)",
		"session.upload_progress.enabled: off, from the image",
		"Note: ConfigMap locked, mounted at /usr/local/etc/php/conf.d, couldn't be read (forbidden)",
		"Settings come from the images and from the ConfigMaps mounted at PHP configuration paths",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("table lacks %q:\n%s", want, buf.String())
		}
	}
	buf.Reset()
	if err := JSON(&buf, res); err != nil || !strings.Contains(buf.String(), `"configMaps": [`) || !strings.Contains(buf.String(), `"uploadProgress": "off-in-fpm-pool"`) {
		t.Errorf("JSON: %v\n%s", err, buf.String())
	}
}

// A file from a ConfigMap counts only where the image's own PHP reads configuration.
// The official php image reads /usr/local/etc/php/php.ini and scans conf.d, never
// php.d or /usr/local/etc/php.ini, so files there can't turn the setting off.
func TestConfigMapsWherePHPReads(t *testing.T) {
	official := map[string]string{
		"/usr/local/etc/php/conf.d/docker-php-ext-sodium.ini": "extension=sodium\n",
		"/usr/local/etc/php-fpm.conf":                         "[global]\ninclude=etc/php-fpm.d/*.conf\n",
		"/usr/local/etc/php-fpm.d/www.conf":                   "[www]\nuser = www-data\n",
	}
	file := func(name, mountPath, configMap, key string) m {
		return configPod("a", name, []m{{"name": "v", "mountPath": mountPath, "subPath": key}}, []m{cmVolume("v", configMap, nil)}, nil)
	}
	pods := []m{
		file("php.d", "/usr/local/etc/php/php.d/zz-off.ini", "off", "zz-off.ini"),
		configPod("a", "etc", []m{{"name": "v", "mountPath": "/usr/local/etc"}}, []m{cmVolume("v", "etc", nil)}, nil),
		file("php.ini", "/usr/local/etc/php/php.ini", "etc", "php.ini"),
		file("conf.d", "/usr/local/etc/php/conf.d/zz-off.ini", "off", "zz-off.ini"),
		file("harmless", "/usr/local/etc/php/php.d/20-gd.ini", "gd", "20-gd.ini"),
		file("pool", "/usr/local/etc/php-fpm.d/zz-off.conf", "pool", "zz-off.conf"),
		file("pool-elsewhere", "/etc/php-fpm.d/zz-off.conf", "pool", "zz-off.conf"),
		// What isn't read can't turn on into off, so on stays on.
		configPod("a", "secret", []m{{"name": "s", "mountPath": "/usr/local/etc/php/conf.d"}}, []m{{"name": "s", "secret": m{"secretName": "php-ini"}}}, nil),
	}
	configMaps := map[string]string{
		"a/off":  cmJSON(map[string]string{"zz-off.ini": "session.upload_progress.enabled = Off\n"}),
		"a/etc":  cmJSON(map[string]string{"php.ini": "session.upload_progress.enabled = 0\n"}),
		"a/gd":   cmJSON(map[string]string{"20-gd.ini": "extension=gd\n"}),
		"a/pool": cmJSON(map[string]string{"zz-off.conf": "[www]\nphp_admin_flag[session.upload_progress.enabled] = off\n"}),
	}
	got, _, _ := checkConfig(t, pods, official, configMaps, nil)
	for name, want := range map[string]struct{ value, text, note string }{
		"php.d": {"unknown", "unknown",
			"ConfigMap off puts /usr/local/etc/php/php.d/zz-off.ini outside the places this image's PHP reads its configuration from, so it was left out; PHP may still read it, and it would change the setting, so the setting is unknown."},
		"etc":      {"unknown", "unknown", "ConfigMap etc puts /usr/local/etc/php.ini outside the places"},
		"php.ini":  {"off", "off, set in ConfigMap etc (/usr/local/etc/php/php.ini)", ""},
		"conf.d":   {"off", "off, set in ConfigMap off (/usr/local/etc/php/conf.d/zz-off.ini)", ""},
		"harmless": {"on", "on, from the image; left out: ConfigMap gd at /usr/local/etc/php/php.d/20-gd.ini", "ConfigMap gd puts /usr/local/etc/php/php.d/20-gd.ini outside the places this image's PHP reads its configuration from, so it was left out."},
		"pool":     {"off-in-fpm-pool", "off in every FPM pool (on in php.ini/conf.d), set in ConfigMap pool (/usr/local/etc/php-fpm.d/zz-off.conf)", ""},
		// The image's php-fpm.conf includes only its own php-fpm.d, so FPM can't read
		// a pool file elsewhere and its off changes nothing.
		"pool-elsewhere": {"on", "on, from the image; left out: ConfigMap pool at /etc/php-fpm.d/zz-off.conf", "ConfigMap pool puts /etc/php-fpm.d/zz-off.conf outside the places"},
		"secret":         {"on", "on, from the image", "A Secret is mounted at /usr/local/etc/php/conf.d"},
	} {
		c := got["a/"+name]
		notes := strings.Join(c.Notes, " ")
		if c.UploadProgress != want.value || uploadText(c) != want.text || want.note == "" && notes != "" || !strings.Contains(notes, want.note) {
			t.Errorf("%s: %q, %q, ConfigMaps %+v, notes %q", name, c.UploadProgress, uploadText(c), c.ConfigMaps, c.Notes)
		}
		// A file PHP doesn't read isn't listed as read, but as left out.
		for _, cm := range c.ConfigMaps {
			for _, f := range cm.Files {
				if strings.Contains(f, "php.d/") || f == "/usr/local/etc/php.ini" || strings.HasPrefix(f, "/etc/") {
					t.Errorf("%s: %s listed as read", name, f)
				}
			}
		}
		if name == "php.d" && (len(c.ConfigMaps) != 1 || !reflect.DeepEqual(c.ConfigMaps[0].LeftOut, []string{"/usr/local/etc/php/php.d/zz-off.ini"})) {
			t.Errorf("left out: %+v", c.ConfigMaps)
		}
	}
}

// withContainer sets a field of a configPod's container.
func withContainer(pod m, key string, value any) m {
	pod["spec"].(m)["containers"].([]m)[0][key] = value
	return pod
}

// Variables from envFrom can move where PHP reads its ini files, and so can PHP's
// command line, so neither leaves an off from the files alone.
func TestConfigMapsEnvFromAndCommand(t *testing.T) {
	envFrom := func(name string, sources ...m) m {
		return withContainer(configPod("a", name, nil, nil, nil), "envFrom", sources)
	}
	cmd := func(name string, command, args []string) m {
		p := withContainer(configPod("a", name, nil, nil, nil), "command", command)
		return withContainer(p, "args", args)
	}
	ref := func(kind, name string, extra m) m {
		r := m{"name": name}
		for k, v := range extra {
			r[k] = v
		}
		return m{kind: r}
	}
	prefixed := ref("configMapRef", "short", nil)
	prefixed["prefix"] = "PHP_"
	otherPrefix := ref("configMapRef", "env", nil)
	otherPrefix["prefix"] = "APP_"
	pods := []m{
		envFrom("scandir", ref("configMapRef", "app", nil), ref("configMapRef", "env", nil)),
		envFrom("prefix", prefixed),
		envFrom("other-prefix", otherPrefix),
		envFrom("harmless", ref("configMapRef", "app", nil)),
		envFrom("forbidden", ref("configMapRef", "locked", nil)),
		envFrom("optional", ref("configMapRef", "gone", m{"optional": true})),
		envFrom("deleted", ref("configMapRef", "gone", nil)),
		envFrom("secret", ref("secretRef", "creds", nil)),
		envFrom("invalid", ref("configMapRef", "--raw=/api", nil)),
		cmd("d-off", []string{"php-fpm"}, []string{"-d", "session.upload_progress.enabled=0"}),
		cmd("d-on", nil, []string{"php-fpm", "-dsession.upload_progress.enabled=On"}),
		cmd("d-on-and-c", []string{"php"}, []string{"-c", "/etc/custom.ini", "--define", "SESSION.upload_progress.enabled"}),
		cmd("c", []string{"docker-php-entrypoint", "php-fpm", "-c", "/etc/custom.ini"}, nil),
		cmd("n-in-shell", []string{"sh", "-c", "exec php-fpm -n"}, nil),
		cmd("php-ini", []string{"/usr/local/sbin/php-fpm8.3", "--php-ini=/etc/custom.ini"}, nil),
		cmd("fpm-config", []string{"php-fpm83", "-y", "/etc/fpm.conf"}, nil),
		cmd("shell", []string{"sh", "-c", "exec php-fpm -F"}, nil),
		cmd("other-d", []string{"php-fpm"}, []string{"-d", "memory_limit=1G"}),
		cmd("other-program", []string{"supervisord", "-c", "/etc/supervisord.conf", "-n"}, nil),
		// Variables a shell or env sets on the command line move PHP's ini files too.
		cmd("prefix-assignment", []string{"sh", "-c"}, []string{"PHP_INI_SCAN_DIR=/srv/ini exec php-fpm"}),
		cmd("env-program", []string{"env", "PHPRC=/srv", "php-fpm"}, nil),
		cmd("export", []string{"sh", "-c", "export PHP_INI_SCAN_DIR=/srv/ini; php-fpm -F"}, nil),
		cmd("shell-variable", []string{"sh", "-c", "PHPRC=$CONF exec php-fpm"}, nil),
		// PHP's options end at its script, and at the end of its command.
		cmd("then-supervisord", []string{"sh", "-c", "php artisan migrate --force && exec supervisord -c /etc/supervisor/supervisord.conf"}, nil),
		cmd("artisan-n", []string{"php", "artisan", "queue:work", "-n"}, nil),
		cmd("console-n", []string{"php"}, []string{"bin/console", "messenger:consume", "async", "-n"}),
		cmd("script-d", []string{"php", "artisan", "serve", "-d", "session.upload_progress.enabled=0"}, nil),
		cmd("file-n", []string{"php", "-f", "/app/worker.php", "-n"}, nil),
		cmd("d-before-script", []string{"php", "-d", "session.upload_progress.enabled=0", "artisan", "serve"}, nil),
		cmd("after-separator", []string{"sh", "-c", "php -v; php-fpm -n"}, nil),
		// Short options can be grouped.
		cmd("grouped-n", []string{"php-fpm", "-Fn"}, nil),
		cmd("grouped-c", []string{"php-fpm", "-Fc", "/etc/custom.ini"}, nil),
		cmd("grouped-other", []string{"php-fpm", "-FR"}, nil),
		// An argument outside a shell's script is one word, spaces and all. PHP quotes
		// a value that starts with a space, so it reads as neither on nor off.
		cmd("d-spaced", []string{"php-fpm", "-d", "session.upload_progress.enabled = On"}, nil),
		cmd("r-spaced", []string{"php", "-r", "echo 1; sleep 1", "-n"}, nil),
		// php-fpm's prefix moves its configuration file and pools.
		cmd("fpm-prefix", []string{"php-fpm", "-p", "/srv/fpm"}, nil),
		cmd("fpm-prefix-long", []string{"php-fpm", "--prefix=/srv/fpm"}, nil),
		// The image's own php.ini and php-fpm.conf change nothing; other paths do.
		cmd("default-ini", []string{"php-fpm", "-c", "/usr/local/etc/php/php.ini"}, nil),
		cmd("default-ini-dir", []string{"php-fpm", "--php-ini", "/usr/local/etc/php/"}, nil),
		cmd("default-fpm-config", []string{"php-fpm", "--fpm-config", "/usr/local/etc/php-fpm.conf", "-c", "/usr/local/etc/php/php.ini"}, nil),
		cmd("relative-ini", []string{"php-fpm", "-c", "php.ini"}, nil),
		cmd("other-ini", []string{"php-fpm", "-c", "/usr/local/etc/php.ini"}, nil),
	}
	configMaps := map[string]string{
		"a/app": cmJSON(map[string]string{"DB_HOST": "db"}),
		"a/env": cmJSON(map[string]string{"PHP_INI_SCAN_DIR": "/srv/empty"}),
		// With the prefix PHP_, RC becomes PHP_RC, not PHPRC.
		"a/short": cmJSON(map[string]string{"INI_SCAN_DIR": "/srv/empty", "RC": "/srv"}),
	}
	got, reads, _ := checkConfig(t, pods, fpmFiles, configMaps, map[string]error{"a/locked": errors.New("forbidden")})
	for name, want := range map[string]struct{ value, note string }{
		"scandir":            {"unknown", `PHP_INI_SCAN_DIR is set to "/srv/empty" by ConfigMap env (envFrom), so PHP may read .ini files from a place whichphp doesn't follow; the setting may differ.`},
		"prefix":             {"unknown", `PHP_INI_SCAN_DIR is set to "/srv/empty" by ConfigMap short (envFrom)`},
		"other-prefix":       {"off", ""},
		"harmless":           {"off", ""},
		"forbidden":          {"unknown", "ConfigMap locked, whose keys the container gets as variables (envFrom), couldn't be read (forbidden)"},
		"optional":           {"off", ""},
		"deleted":            {"unknown", "ConfigMap gone, whose keys the container gets as variables (envFrom), doesn't exist any more"},
		"secret":             {"unknown", "Secret creds, whose keys the container gets as variables (envFrom), isn't read"},
		"invalid":            {"unknown", "couldn't be read (not a valid ConfigMap name)"},
		"d-off":              {"unknown", `The container's command line passes -d session.upload_progress.enabled=0 to PHP, which can change the setting, so it is unknown.`},
		"d-on":               {"on", "passes -d session.upload_progress.enabled=On to PHP, which turns the setting on, whatever the files say."},
		"d-on-and-c":         {"on", "passes -c /etc/custom.ini, -d SESSION.upload_progress.enabled to PHP, which turns the setting on"},
		"c":                  {"unknown", "passes -c /etc/custom.ini to PHP"},
		"n-in-shell":         {"unknown", "passes -n to PHP"},
		"php-ini":            {"unknown", "passes --php-ini=/etc/custom.ini to PHP"},
		"fpm-config":         {"unknown", "passes -y /etc/fpm.conf to PHP"},
		"shell":              {"off", ""},
		"other-d":            {"off", ""},
		"other-program":      {"off", ""},
		"prefix-assignment":  {"unknown", `PHP_INI_SCAN_DIR is set to "/srv/ini" in the container's command line, so PHP may read .ini files from a place whichphp doesn't follow; the setting may differ.`},
		"env-program":        {"unknown", `PHPRC is set to "/srv" in the container's command line, so PHP may read its php.ini`},
		"export":             {"unknown", `PHP_INI_SCAN_DIR is set to "/srv/ini" in the container's command line`},
		"shell-variable":     {"unknown", "PHPRC is set, to a value the pod spec doesn't show, in the container's command line"},
		"then-supervisord":   {"off", ""},
		"artisan-n":          {"off", ""},
		"console-n":          {"off", ""},
		"script-d":           {"off", ""},
		"file-n":             {"off", ""},
		"d-before-script":    {"unknown", "passes -d session.upload_progress.enabled=0 to PHP"},
		"after-separator":    {"unknown", "passes -n to PHP"},
		"grouped-n":          {"unknown", "passes -Fn to PHP"},
		"grouped-c":          {"unknown", "passes -Fc /etc/custom.ini to PHP"},
		"grouped-other":      {"off", ""},
		"d-spaced":           {"unknown", "passes -d session.upload_progress.enabled = On to PHP, which can change the setting, so it is unknown."},
		"r-spaced":           {"off", ""},
		"fpm-prefix":         {"unknown", "passes -p /srv/fpm to PHP"},
		"fpm-prefix-long":    {"unknown", "passes --prefix=/srv/fpm to PHP"},
		"default-ini":        {"off", ""},
		"default-ini-dir":    {"off", ""},
		"default-fpm-config": {"off", ""},
		"relative-ini":       {"unknown", "passes -c php.ini to PHP"},
		"other-ini":          {"unknown", "passes -c /usr/local/etc/php.ini to PHP"},
	} {
		c := got["a/"+name]
		notes := strings.Join(c.Notes, " ")
		if c.UploadProgress != want.value || want.note == "" && notes != "" || !strings.Contains(notes, want.note) {
			t.Errorf("%s: %q, notes %q", name, c.UploadProgress, c.Notes)
		}
	}
	// Each ConfigMap is read once; a name kubectl could take for a flag never is.
	for cm, want := range map[string]int{"a/app": 1, "a/env": 1, "a/short": 1, "a/locked": 1, "a/gone": 1} {
		if reads[cm] != want {
			t.Errorf("%s read %d times, want %d", cm, reads[cm], want)
		}
	}
	if len(reads) != 5 {
		t.Errorf("reads: %v", reads)
	}
}

// Containers without PHP, or that couldn't be checked, read no ConfigMaps.
func TestConfigMapsOnlyForPHP(t *testing.T) {
	b, _ := json.Marshal(m{"items": []m{configPod("a", "p", []m{{"name": "ext", "mountPath": "/usr/local/etc/php/conf.d"}}, []m{cmVolume("ext", "ext", nil)}, nil)}})
	cs, _, _ := Inventory(b, nil, InventoryOptions{})
	for _, scan := range []Scanner{
		func(context.Context, string, string) (verdict.Report, error) {
			return rep(verdict.ActionNoPHP, "", ""), nil
		},
		func(context.Context, string, string) (verdict.Report, error) {
			return verdict.Report{}, errors.New("manifest unknown")
		},
	} {
		read := func(context.Context, string, string) ([]byte, error) {
			t.Error("read a ConfigMap for a container without PHP")
			return nil, nil
		}
		res := Check(context.Background(), cs, scan, fakeResolve, CheckOptions{ReadConfigMap: read})
		if c := res.Workloads[0].Containers[0]; c.UploadProgress != "" || len(c.ConfigMaps) != 0 {
			t.Errorf("%+v", c)
		}
	}
}

// Pods of one workload that mount different ConfigMaps are reported apart; pods
// that differ only in their generated token volume are not.
func TestConfigMapsSplitWorkloads(t *testing.T) {
	pod := func(name, hash, configMap, token string) m {
		p := configPod("shop", name, []m{{"name": "ini", "mountPath": "/usr/local/etc/php/conf.d"}, {"name": token, "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"}},
			[]m{cmVolume("ini", configMap, nil), {"name": token, "projected": m{"sources": []m{{"serviceAccountToken": m{"path": "token"}}}}}}, nil)
		md := p["metadata"].(m)
		md["labels"] = m{"pod-template-hash": hash}
		md["ownerReferences"] = []m{{"kind": "ReplicaSet", "name": "web-" + hash, "controller": true}}
		return p
	}
	b, _ := json.Marshal(m{"items": []m{pod("web-1-a", "1", "ini-v1", "kube-api-access-aaaaa"), pod("web-1-b", "1", "ini-v1", "kube-api-access-bbbbb"), pod("web-2-a", "2", "ini-v2", "kube-api-access-ccccc")}})
	cs, _, err := Inventory(b, nil, InventoryOptions{})
	if err != nil || len(cs) != 2 || len(cs[0].Pods)+len(cs[1].Pods) != 3 {
		t.Fatalf("%v: %+v", err, cs)
	}
}

func TestEnvironment(t *testing.T) {
	var c podContainer
	if err := json.Unmarshal([]byte(`{"env":[
		{"name":"A","value":"x"},
		{"name":"B","value":"$(A)/y"},
		{"name":"C","value":"$$(A)"},
		{"name":"D","value":"$(NOPE)"},
		{"name":"E","valueFrom":{"fieldRef":{"fieldPath":"metadata.name"}}},
		{"name":"F","value":"$(E)/z"},
		{"name":"G","value":"$(A"},
		{"name":"H","value":"a$b$"},
		{"name":"A","value":"later"}]}`), &c); err != nil {
		t.Fatal(err)
	}
	e := newEnvironment(c)
	for name, want := range map[string]struct {
		value      string
		known, set bool
	}{
		"A": {"later", true, true}, "B": {"x/y", true, true}, "C": {"$(A)", true, true}, "D": {"$(NOPE)", true, true},
		"E": {"", false, true}, "F": {"", false, true}, "G": {"$(A", true, true}, "H": {"a$b$", true, true}, "Z": {"", false, false},
	} {
		if v, known, set := e.get(name); v != want.value || known != want.known || set != want.set {
			t.Errorf("%s: %q %v %v, want %+v", name, v, known, set, want)
		}
	}
	for _, tc := range []struct {
		in, want string
		strict   bool
		ok       bool
	}{
		{"$(B)", "x/y", true, true},
		{"$(E)", "", true, false},
		{"$(NOPE)", "", true, false},
		{"$(NOPE)", "$(NOPE)", false, true},
		{"$$(B)", "$(B)", true, true},
	} {
		if got, ok := e.expand(tc.in, tc.strict); ok != tc.ok || ok && got != tc.want {
			t.Errorf("expand(%q, %v) = %q, %v", tc.in, tc.strict, got, ok)
		}
	}
	// With envFrom, any variable may be set to anything.
	c.EnvFrom = []envFromSource{{ConfigMapRef: &objectRef{Name: "env"}}}
	if _, ok := newEnvironment(c).expand("$(NOPE)", false); ok {
		t.Error("a variable envFrom may set counted as unset")
	}
}

func TestExposure(t *testing.T) {
	type pod struct {
		ns, name, digest, podStart, started string
		init                                bool
	}
	mk := func(p pod) m {
		status := m{"name": "c", "imageID": "docker.io/library/php@" + d(p.digest[0])}
		if p.started != "" {
			status["state"] = m{"running": m{"startedAt": p.started}}
		} else {
			status["state"] = m{"waiting": m{"reason": "CrashLoopBackOff"}}
		}
		spec, st := m{"containers": []m{{"name": "c", "image": "php:8.4"}}}, m{"phase": "Running", "startTime": p.podStart, "containerStatuses": []m{status}}
		if p.init {
			status["state"] = m{"terminated": m{"startedAt": p.podStart}}
			spec["initContainers"] = []m{{"name": "c", "image": "php:8.4"}}
			spec["containers"] = []m{{"name": "main", "image": "php:8.4-fixed"}}
			st["initContainerStatuses"] = []m{status}
			st["containerStatuses"] = []m{{"name": "main", "imageID": "docker.io/library/php@" + d('b'), "state": m{"running": m{"startedAt": p.started}}}}
		}
		return m{"metadata": m{"namespace": p.ns, "name": p.name, "ownerReferences": []m{{"kind": "StatefulSet", "name": p.ns, "controller": true}}}, "spec": spec, "status": st}
	}
	b, _ := json.Marshal(m{"items": []m{
		// The pod's start counts, not its container's: a container restarted since
		// ran the same image before.
		mk(pod{"old", "old-0", "a", "2026-10-10T00:00:00Z", "2026-10-12T08:00:00Z", false}),
		mk(pod{"old", "old-1", "a", "2026-10-20T00:00:00Z", "2026-10-20T10:00:00Z", false}),
		// Without the pod's start time, the running container's start is all there is.
		mk(pod{"nostart", "s-0", "a", "", "2026-10-15T06:00:00Z", false}),
		// A restarting container has run since its pod started.
		mk(pod{"waiting", "w-0", "a", "2026-10-25T00:00:00Z", "", false}),
		mk(pod{"eol", "e-0", "c", "2026-09-01T00:00:00Z", "2026-09-01T00:00:05Z", false}),
		mk(pod{"fixed", "f-0", "b", "2026-09-01T00:00:00Z", "2026-09-01T00:00:05Z", false}),
		mk(pod{"unsure", "u-0", "7", "2026-09-01T00:00:00Z", "2026-09-01T00:00:05Z", false}),
		mk(pod{"fresh", "n-0", "a", "2026-11-01T09:00:00Z", "2026-11-01T10:00:00Z", false}),
		// An init container that has finished isn't running vulnerable PHP now.
		mk(pod{"init", "i-0", "a", "2026-09-01T00:00:00Z", "2026-09-01T00:00:05Z", true}),
	}})
	cs, _, err := Inventory(b, nil, InventoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	scan := func(_ context.Context, input, _ string) (verdict.Report, error) {
		switch {
		case strings.HasSuffix(input, d('b')):
			return rep(verdict.ActionOK, "8.4.27", verdict.Fixed), nil
		case strings.HasSuffix(input, d('c')):
			return rep(verdict.ActionNeeded, "8.1.33", verdict.VulnerableEOL), nil
		case strings.HasSuffix(input, d('7')):
			return rep(verdict.ActionUnknown, "8.4.27", verdict.Unknown), nil
		}
		return rep(verdict.ActionNeeded, "8.4.26", verdict.Vulnerable), nil
	}
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	res := Check(context.Background(), cs, scan, func(context.Context, string) (string, error) { return d('a'), nil }, CheckOptions{Now: func() time.Time { return now }})
	wl := map[string]Workload{}
	for _, w := range res.Workloads {
		wl[w.Namespace] = w
	}
	for ns, want := range map[string]*Exposure{
		"old":     {Since: "2026-10-10T00:00:00Z", Days: 22},
		"nostart": {Since: "2026-10-15T06:00:00Z", Days: 17},
		"waiting": {Since: "2026-10-25T00:00:00Z", Days: 7},
		"eol":     {Since: "2026-09-01T00:00:00Z", Days: 61},
		"fresh":   {Since: "2026-11-01T09:00:00Z", Days: 0},
		"fixed":   nil,
		"unsure":  nil,
		"init":    nil,
	} {
		got := wl[ns].Exposure
		if (got == nil) != (want == nil) || got != nil && *got != *want {
			t.Errorf("%s: exposure %+v, want %+v", ns, got, want)
		}
	}
	if c := wl["old"].Containers[0]; c.Started != "2026-10-10T00:00:00Z" {
		t.Errorf("container start: %q", c.Started)
	}
	var buf bytes.Buffer
	if err := Table(&buf, res); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ACTION NEEDED  old/StatefulSet/old\n  running vulnerable PHP since Oct 10, 2026, 22 days\n",
		"running vulnerable PHP since Nov 1, 2026, less than a day",
		"running vulnerable PHP since Oct 25, 2026, 7 days",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("table lacks %q:\n%s", want, buf.String())
		}
	}
	buf.Reset()
	if err := JSON(&buf, res); err != nil || !strings.Contains(buf.String(), `"exposure": {
        "since": "2026-10-10T00:00:00Z",
        "days": 22
      }`) {
		t.Errorf("JSON: %v\n%s", err, buf.String())
	}
	// A pod that may run another image than the one checked doesn't count.
	unverified := Container{Namespace: "loaded", Kind: "Pod", Workload: "p", Name: "c", Image: "php:8.4", LocalID: d('9'), Pods: []string{"p"}, started: now.Add(-48 * time.Hour)}
	res = Check(context.Background(), []Container{unverified}, func(context.Context, string, string) (verdict.Report, error) {
		r := rep(verdict.ActionNeeded, "8.4.26", verdict.Vulnerable)
		r.Image.ImageID = d('8')
		return r, nil
	}, nil, CheckOptions{Now: func() time.Time { return now }})
	if w := res.Workloads[0]; w.Exposure != nil || !w.Containers[0].RunningUnverified {
		t.Errorf("unverified: %+v", w)
	}
}

func TestFromDocker(t *testing.T) {
	images := map[string]string{
		"php@" + d('a'): `[{"Id":"` + d('5') + `","RepoDigests":["php@` + d('a') + `"],"Os":"linux","Architecture":"arm64"}]`,
		d('8'):          `[{"Id":"` + d('8') + `","RepoDigests":[],"Os":"linux","Architecture":"arm64"}]`,
		"php@" + d('c'): `[{"Id":"` + d('6') + `","RepoDigests":["php@` + d('c') + `"],"Os":"linux","Architecture":"amd64"}]`,
		"php@" + d('e'): `[{"Id":"` + d('6') + `","RepoDigests":["php@` + d('f') + `"],"Os":"linux","Architecture":"arm64"}]`,
		"php@" + d('2'): `[{"Id":"sha256:short; rm -rf /","RepoDigests":["php@` + d('2') + `"]}]`,
		// Docker describes these as arm64, but Syft reads them as amd64.
		"php@" + d('3'): `[{"Id":"` + d('7') + `","RepoDigests":["php@` + d('3') + `"],"Os":"linux","Architecture":"arm64"}]`,
		"php@" + d('4'): `[{"Id":"` + d('1') + `","RepoDigests":["php@` + d('4') + `"],"Os":"linux","Architecture":"arm64"}]`,
		"php@" + d('9'): `[{"Id":"` + d('0') + `","RepoDigests":["php@` + d('9') + `"],"Os":"linux","Architecture":"amd64"}]`,
	}
	inspected := map[string]int{}
	inspect := func(_ context.Context, ref string) ([]byte, error) {
		inspected[ref]++
		ref = strings.TrimPrefix(ref, "docker.io/library/") // as Docker does
		if ref == "php@"+d('d') {
			return nil, errors.New("docker image inspect failed; its message is on stderr")
		}
		if b, ok := images[ref]; ok {
			return []byte(b), nil
		}
		return nil, ErrNotFound
	}
	var scans []string
	scan := func(_ context.Context, input, platform string) (verdict.Report, error) {
		scans = append(scans, input+"|"+platform)
		r := rep(verdict.ActionNeeded, "8.4.26", verdict.Vulnerable)
		r.Image.ImageID = "id-" + input
		switch input {
		case "docker:" + d('7'), "docker:" + d('1'), "docker:" + d('0'):
			r.Image.Architecture = "amd64"
		default:
			r.Image.Architecture = "arm64"
		}
		return r, nil
	}
	mk := func(ns, running, local string) Container {
		return Container{Namespace: ns, Kind: "Pod", Workload: "p", Name: "c", Image: "php:8.4", Running: running, LocalID: local, Platform: "linux/arm64", Pods: []string{ns}}
	}
	// Without the node's platform, Docker's says what Syft must read.
	noNode := func(ns, running string) Container {
		c := mk(ns, running, "")
		c.Platform = ""
		return c
	}
	res := Check(context.Background(), []Container{
		mk("digest", "php@"+d('a'), ""), mk("digest-again", "docker.io/library/php@"+d('a'), ""), mk("digest-twice", "php@"+d('a'), ""),
		mk("local", "", d('8')), mk("absent", "php@"+d('b'), ""), mk("platform", "php@"+d('c'), ""),
		mk("broken", "php@"+d('d'), ""), mk("other", "php@"+d('e'), ""), mk("bad-id", "php@"+d('2'), ""), mk("tag-only", "", ""),
		mk("read-other-arch", "php@"+d('3'), ""), noNode("no-node", "php@"+d('4')), noNode("no-node-same", "php@"+d('9')),
	}, scan, func(context.Context, string) (string, error) { return d('a'), nil }, CheckOptions{Docker: inspect})
	got := map[string]ContainerResult{}
	for _, w := range res.Workloads {
		got[w.Namespace] = w.Containers[0]
	}
	for ns, want := range map[string]struct {
		input string
		note  string
	}{
		"digest":       {"docker:" + d('5'), ""},
		"digest-again": {"docker:" + d('5'), ""},
		"local":        {"docker:" + d('8'), ""},
		"absent":       {"registry:php@" + d('b'), "The image isn't in the local Docker daemon, so it was read from its registry."},
		"platform":     {"registry:php@" + d('c'), "The local Docker daemon has this image for linux/amd64, not for the node's linux/arm64"},
		"broken":       {"registry:php@" + d('d'), "Couldn't ask the local Docker daemon (docker image inspect failed; its message is on stderr)"},
		"other":        {"registry:php@" + d('e'), "isn't in the local Docker daemon"},
		"bad-id":       {"registry:php@" + d('2'), "isn't in the local Docker daemon"},
		"tag-only":     {"registry:php:8.4", "reported no image digest or ID to look up in the local Docker daemon"},
		"read-other-arch": {"registry:php@" + d('3'),
			"Syft read the local Docker daemon's image for amd64, not for arm64, so it was read from its registry."},
		"no-node":      {"registry:php@" + d('4'), "Syft read the local Docker daemon's image for amd64, not for arm64"},
		"no-node-same": {"docker:" + d('0'), ""},
	} {
		c := got[ns]
		if c.Result.Input != want.input || c.FromDocker != strings.HasPrefix(want.input, "docker:") || want.note != "" && !strings.Contains(strings.Join(c.Notes, " "), want.note) || want.note == "" && len(c.Notes) != 0 {
			t.Errorf("%s: input %q, from Docker %v, notes %q", ns, c.Result.Input, c.FromDocker, c.Notes)
		}
	}
	// Each reference is inspected once, and a Docker image is read as it is, without
	// a platform, so Syft never pulls.
	if inspected["php@"+d('a')] != 1 || inspected["docker.io/library/php@"+d('a')] != 1 {
		t.Errorf("inspections: %v", inspected)
	}
	for _, s := range scans {
		if strings.HasPrefix(s, "docker:") && !strings.HasSuffix(s, "|") {
			t.Errorf("Docker image read for a platform: %s", s)
		}
	}
	// An image Syft read for another architecture is read again, for the node's.
	if !slices.Contains(scans, "registry:php@"+d('3')+"|linux/arm64") || !slices.Contains(scans, "docker:"+d('7')+"|") {
		t.Errorf("scans: %q", scans)
	}
	// An image known only by its ID can't be compared with its tag.
	if a := got["local"].Advice; !strings.Contains(a, "built or loaded locally") {
		t.Errorf("local advice: %q", a)
	}
	var buf bytes.Buffer
	if err := Table(&buf, res); err != nil || !strings.Contains(buf.String(), "running sha256:aaaaaaaaaaaa…, read from the local Docker daemon") ||
		!strings.Contains(buf.String(), "running image ID sha256:888888888888…, read from the local Docker daemon") {
		t.Errorf("table: %v\n%s", err, buf.String())
	}
}

// A scan that needed a second download says so.
func TestRetriedScanIsReported(t *testing.T) {
	scan := func(context.Context, string, string) (verdict.Report, error) {
		r := rep(verdict.ActionOK, "8.4.27", verdict.Fixed)
		r.Image.ReadRetried = "unexpected EOF"
		return r, nil
	}
	c := Container{Namespace: "a", Kind: "Pod", Workload: "p", Name: "c", Image: "php@" + d('b'), Running: "php@" + d('b'), Pods: []string{"p"}}
	res := Check(context.Background(), []Container{c}, scan, fakeResolve, CheckOptions{})
	cr := res.Workloads[0].Containers[0]
	if cr.Result.Retried != "unexpected EOF" || len(cr.Notes) != 1 || cr.Notes[0] != "Syft's first download of this image was cut off (unexpected EOF), so it was read a second time." {
		t.Errorf("%+v", cr)
	}
	var buf bytes.Buffer
	if err := Table(&buf, res); err != nil || !strings.Contains(buf.String(), "Note: Syft's first download of this image was cut off") {
		t.Errorf("table: %v\n%s", err, buf.String())
	}
}

// FuzzConfigMap: ConfigMaps come from the cluster's API server, and so do the pod
// specs that mount them. Laying them over an image's files must never panic, every
// mounted file must sit at a clean absolute path under its mount, and the setting
// must be one of the documented values, and never off when something that could
// change it wasn't read.
func FuzzConfigMap(f *testing.F) {
	pods, _ := json.Marshal(m{"items": []m{
		configPod("a", "p", []m{{"name": "ini", "mountPath": "/usr/local/etc/php/conf.d/zz.ini", "subPath": "zz.ini"}, {"name": "etc", "mountPath": "/usr/local/etc/php", "subPathExpr": "$(X)"}},
			[]m{cmVolume("ini", "php-ini", nil), cmVolume("etc", "etc", m{"items": []m{{"key": "k", "path": "conf.d/../x.ini"}}, "optional": true})}, []m{{"name": "X", "value": "conf.d"}}),
	}})
	f.Add(pods, []byte(cmJSON(map[string]string{"zz.ini": "session.upload_progress.enabled = Off\n", "k": "x"})))
	f.Add(pods, []byte(`{"kind":"ConfigMap","binaryData":{"zz.ini":"c2Vzc2lvbi51cGxvYWRfcHJvZ3Jlc3MuZW5hYmxlZD0w"}}`))
	// A command line and envFrom, which can move or set the setting too.
	withCmd, _ := json.Marshal(m{"items": []m{withContainer(withContainer(configPod("a", "c", nil, nil, nil),
		"command", []string{"sh", "-c", "PHPRC=/x php-fpm -Fn -dsession.upload_progress.enabled=1 && supervisord -c x"}),
		"envFrom", []m{{"configMapRef": m{"name": "env"}, "prefix": "PHP_"}, {"secretRef": m{"name": "s"}}})}})
	f.Add(withCmd, []byte(cmJSON(map[string]string{"INI_SCAN_DIR": "/srv"})))
	f.Fuzz(func(t *testing.T, pods, configMap []byte) {
		if data, err := ParseConfigMap(configMap); err == nil && data == nil {
			t.Fatal("no error and no data")
		}
		cs, _, err := Inventory(pods, nil, InventoryOptions{})
		if err != nil {
			return
		}
		read := func(context.Context, string, string) ([]byte, error) { return configMap, nil }
		scan := func(context.Context, string, string) (verdict.Report, error) {
			return withFiles(verdict.ActionNeeded, "8.4.26", verdict.Vulnerable, fpmFiles), nil
		}
		res := Check(context.Background(), cs, scan, func(context.Context, string) (string, error) { return "", nil }, CheckOptions{ReadConfigMap: read})
		for _, w := range res.Workloads {
			for _, c := range w.Containers {
				switch c.UploadProgress {
				case "on", "off", "off-in-fpm-pool", "unknown", "":
				default:
					t.Fatalf("unexpected value %q", c.UploadProgress)
				}
				// Off only when everything that could change it was read.
				for _, n := range c.Notes {
					if strings.HasSuffix(n, "the setting may differ.") && strings.HasPrefix(c.UploadProgress, "off") {
						t.Fatalf("%s, but: %s", c.UploadProgress, n)
					}
				}
				for _, cm := range c.ConfigMaps {
					for _, file := range append(append([]string(nil), cm.Files...), cm.LeftOut...) {
						if !path.IsAbs(file) || path.Clean(file) != file || !under(file, cm.MountPath) {
							t.Fatalf("mounted file %q outside %q", file, cm.MountPath)
						}
					}
				}
			}
		}
	})
}

// FuzzDockerInspect: "docker image inspect" output names the image whichphp hands
// to Syft, so whatever it says, only a well-formed image ID may come back.
func FuzzDockerInspect(f *testing.F) {
	f.Add([]byte(`[{"Id":"`+d('5')+`","RepoDigests":["php@`+d('a')+`"],"Os":"linux","Architecture":"arm64"}]`), "php@"+d('a'), "")
	f.Add([]byte(`[{"Id":"`+d('8')+`"}]`), "", d('8'))
	f.Fuzz(func(t *testing.T, b []byte, running, local string) {
		id, _, err := MatchDockerImage(b, running, local)
		if err != nil || id == "" {
			return
		}
		if LocalID(id) != id {
			t.Fatalf("not an image ID: %q", id)
		}
	})
}
