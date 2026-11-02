package phpini

import (
	"strings"
	"testing"
)

func TestNoConfigFilesMeansCompiledDefault(t *testing.T) {
	r := Evaluate(map[string]string{}, true)
	if got := r.Settings[UploadProgress].Effective; got != "on" {
		t.Fatalf("upload_progress = %q, want on (compiled default)", got)
	}
}

func TestWithoutContentIsUnknown(t *testing.T) {
	r := Evaluate(nil, false)
	if got := r.Settings[UploadProgress].Effective; got != "unknown" {
		t.Fatalf("upload_progress = %q, want unknown", got)
	}
}

func TestOffInConfD(t *testing.T) {
	files := map[string]string{
		"/usr/local/etc/php/conf.d/zz-whichphp.ini": "; mitigation\nsession.upload_progress.enabled = Off\n",
	}
	r := Evaluate(files, true)
	if got := r.Settings[UploadProgress].Effective; got != "off" {
		t.Fatalf("upload_progress = %q, want off", got)
	}
}

func TestConfDOverridesPhpIni(t *testing.T) {
	files := map[string]string{
		"/etc/php/8.3/fpm/php.ini":                "session.upload_progress.enabled = On\n",
		"/etc/php/8.3/fpm/conf.d/99-mitigate.ini": "session.upload_progress.enabled=0\n",
		"/etc/php/8.3/cli/php.ini":                "session.upload_progress.enabled = On\n",
	}
	r := Evaluate(files, true)
	if got := r.Settings[UploadProgress].Effective; got != "off" {
		t.Fatalf("upload_progress = %q, want off (CLI tree ignored, conf.d wins)", got)
	}
}

func TestOffOnlyInFPMPool(t *testing.T) {
	files := map[string]string{
		"/usr/local/etc/php-fpm.d/www.conf": "[www]\nphp_admin_flag[session.upload_progress.enabled] = off\n",
	}
	r := Evaluate(files, true)
	if got := r.Settings[UploadProgress].Effective; got != "off-in-fpm-pool" {
		t.Fatalf("upload_progress = %q, want off-in-fpm-pool", got)
	}
}

func TestOnInFPMPool(t *testing.T) {
	cases := map[string]map[string]string{
		"pool on overrides php.ini off": {
			"/usr/local/etc/php/php.ini":        "session.upload_progress.enabled=0\n",
			"/usr/local/etc/php-fpm.d/www.conf": "[www]\nphp_admin_flag[session.upload_progress.enabled]=on\n",
		},
		"one pool on, another off": {
			"/usr/local/etc/php-fpm.d/a.conf": "[a]\nphp_admin_flag[session.upload_progress.enabled]=off\n",
			"/usr/local/etc/php-fpm.d/b.conf": "[b]\nphp_value[session.upload_progress.enabled]=1\n",
		},
		"pool turns it off, then on again": {
			"/usr/local/etc/php/conf.d/off.ini": "session.upload_progress.enabled=Off\n",
			"/usr/local/etc/php-fpm.d/www.conf": "[www]\nphp_admin_flag[session.upload_progress.enabled]=off\nphp_admin_flag[session.upload_progress.enabled]=on\n",
		},
		"pool value from the environment": {
			"/usr/local/etc/php/php.ini":        "session.upload_progress.enabled=0\n",
			"/usr/local/etc/php-fpm.d/www.conf": "[www]\nphp_value[session.upload_progress.enabled]=${UPLOAD_PROGRESS}\n",
		},
	}
	for name, files := range cases {
		s := Evaluate(files, true).Settings[UploadProgress]
		if s.Effective != "on" {
			t.Errorf("%s: upload_progress = %q (%s), want on", name, s.Effective, s.Why)
		}
	}
	if s := Evaluate(cases["one pool on, another off"], true).Settings[UploadProgress]; s.Why != "turned on in one FPM pool and off in another" {
		t.Errorf("why %q", s.Why)
	}
	if s := Evaluate(cases["pool turns it off, then on again"], true).Settings[UploadProgress]; len(s.SetIn) != 2 {
		t.Errorf("set in %v: want each file once", s.SetIn)
	}
}

// Each FPM pool serves with its own value, or with php.ini's when it sets none.
func TestFPMPoolsEach(t *testing.T) {
	ini := map[string]string{"/usr/local/etc/php/php.ini": "session.upload_progress.enabled=on\n"}
	for name, c := range map[string]struct{ pools, want string }{
		"one pool off, one inherits on": {"[a]\nlisten=9000\nphp_admin_flag[session.upload_progress.enabled]=off\n[b]\nlisten=9001\n", "on"},
		"every pool off":                {"[a]\nphp_admin_flag[session.upload_progress.enabled]=off\n[b]\nphp_value[session.upload_progress.enabled]=0\n", "off-in-fpm-pool"},
		"same pool in two sections":     {"[www]\nlisten=9000\n[global]\nerror_log=/proc/self/fd/2\n[WWW]\nphp_admin_flag[session.upload_progress.enabled]=off\n", "off-in-fpm-pool"},
		"no pool overrides":             {"[www]\nlisten=9000\n", "on"},
		"header with a comment":         {"[a]\nphp_admin_flag[session.upload_progress.enabled]=off\n[b] ; second pool\nlisten=9001\n", "on"},
		"override before any section":   {"php_admin_flag[session.upload_progress.enabled]=off\n[www]\nlisten=9000\n", "on"},
	} {
		files := map[string]string{"/usr/local/etc/php-fpm.d/www.conf": c.pools}
		for k, v := range ini {
			files[k] = v
		}
		s := Evaluate(files, true).Settings[UploadProgress]
		if s.Effective != c.want {
			t.Errorf("%s: upload_progress = %q (%s), want %s", name, s.Effective, s.Why, c.want)
		}
		if name == "one pool off, one inherits on" && s.Why != "on in php.ini/conf.d; an FPM pool turns it off, but another pool doesn't" {
			t.Errorf("%s: why %q", name, s.Why)
		}
	}
	// Pools in different files are still one pool when they share a name, as in the
	// official image's www.conf and zz-docker.conf.
	files := map[string]string{
		"/usr/local/etc/php/php.ini":              "session.upload_progress.enabled=on\n",
		"/usr/local/etc/php-fpm.d/www.conf":       "[www]\nphp_admin_flag[session.upload_progress.enabled]=off\n",
		"/usr/local/etc/php-fpm.d/zz-docker.conf": "[global]\ndaemonize = no\n[www]\nlisten = 9000\n",
	}
	if s := Evaluate(files, true).Settings[UploadProgress]; s.Effective != "off-in-fpm-pool" {
		t.Errorf("www across two files: %q (%s)", s.Effective, s.Why)
	}
}

// A pool serves only from a file php-fpm.conf includes, and a quoted section name is
// the same pool as the plain one.
func TestFPMPoolsIncludedAndQuoted(t *testing.T) {
	off := "[www]\nlisten=9000\nphp_admin_flag[session.upload_progress.enabled]=off\n"
	for name, c := range map[string]struct {
		files map[string]string
		want  string
	}{
		"spare file not included": {map[string]string{
			"/usr/local/etc/php-fpm.conf":         "[global]\ninclude=/usr/local/etc/php-fpm.d/www.conf\n",
			"/usr/local/etc/php-fpm.d/www.conf":   off,
			"/usr/local/etc/php-fpm.d/spare.conf": "[spare]\nlisten=9001\n",
		}, "off-in-fpm-pool"},
		"spare file not included, relative path": {map[string]string{
			"/usr/local/etc/php-fpm.conf":         "[global]\ninclude=etc/php-fpm.d/www.conf\n",
			"/usr/local/etc/php-fpm.d/www.conf":   off,
			"/usr/local/etc/php-fpm.d/spare.conf": "[spare]\nlisten=9001\n",
		}, "off-in-fpm-pool"},
		"spare file included by a relative glob": {map[string]string{
			"/usr/local/etc/php-fpm.conf":         "[global]\ninclude=etc/php-fpm.d/*.conf ; the official image's line\n",
			"/usr/local/etc/php-fpm.d/www.conf":   off,
			"/usr/local/etc/php-fpm.d/spare.conf": "[spare]\nlisten=9001\n",
		}, "on"},
		"include through an included file": {map[string]string{
			"/etc/php/8.3/fpm/php-fpm.conf":       "include=\"/etc/php/8.3/fpm/pool.d/www.conf\"\n",
			"/etc/php/8.3/fpm/pool.d/www.conf":    off + "include=/etc/php/8.3/fpm/pool.d/z*.conf\n",
			"/etc/php/8.3/fpm/pool.d/zspare.conf": "[spare]\nlisten=9001\n",
		}, "on"},
		"include with a variable": {map[string]string{
			"/usr/local/etc/php-fpm.conf":         "[global]\ninclude=${prefix}/etc/php-fpm.d/www.conf\n",
			"/usr/local/etc/php-fpm.d/www.conf":   off,
			"/usr/local/etc/php-fpm.d/spare.conf": "[spare]\nlisten=9001\n",
		}, "on"},
		"include that matches nothing": {map[string]string{
			"/usr/local/etc/php-fpm.conf":         "[global]\ninclude=/srv/fpm/*.conf\n",
			"/usr/local/etc/php-fpm.d/www.conf":   off,
			"/usr/local/etc/php-fpm.d/spare.conf": "[spare]\nlisten=9001\n",
		}, "on"},
		"glob negation": {map[string]string{
			"/usr/local/etc/php-fpm.conf":             "[global]\ninclude=\"/usr/local/etc/php-fpm.d/[!_]*.conf\"\n",
			"/usr/local/etc/php-fpm.d/zz-upload.conf": off,
			"/usr/local/etc/php-fpm.d/zz-app.conf":    "[app]\nlisten=9001\n",
			"/usr/local/etc/php-fpm.d/_old.conf":      "[www]\nlisten=9000\n",
		}, "on"},
		// A file with only the override line continues the section the file before
		// it ended in: zz-docker.conf's [www].
		"override in a file without a section": {map[string]string{
			"/usr/local/etc/php-fpm.conf":             "[global]\ninclude=etc/php-fpm.d/*.conf\n",
			"/usr/local/etc/php-fpm.d/www.conf":       "[www]\nuser = www-data\n",
			"/usr/local/etc/php-fpm.d/zz-docker.conf": "[global]\ndaemonize = no\n[www]\nlisten = 9000\n",
			"/usr/local/etc/php-fpm.d/zz-upload.conf": "php_admin_flag[session.upload_progress.enabled] = off\n",
		}, "off-in-fpm-pool"},
		// ... but not into a file FPM doesn't include, or when there's no php-fpm.conf
		// to show what it includes.
		"override in a stray file": {map[string]string{
			"/usr/local/etc/php-fpm.conf":                 "[global]\ninclude=/usr/local/etc/php-fpm.d/*.conf\n",
			"/usr/local/etc/php-fpm.d/www.conf":           "[www]\nlisten = 9000\n",
			"/usr/local/etc/php-fpm.d.bak/zz-upload.conf": "php_admin_flag[session.upload_progress.enabled] = off\n",
		}, "on"},
		"off in a pool file FPM doesn't include": {map[string]string{
			"/usr/local/etc/php-fpm.conf":         "[global]\ninclude=/usr/local/etc/php-fpm.d/www.conf\n",
			"/usr/local/etc/php-fpm.d/www.conf":   "[www]\nlisten = 9000\n",
			"/usr/local/etc/php-fpm.d/spare.conf": off,
		}, "on"},
		"override with no php-fpm.conf": {map[string]string{
			"/etc/php/8.3/fpm/pool.d/www.conf":      "[www]\nlisten = 9000\n",
			"/opt/app/docker/php-fpm.d/upload.conf": "php_admin_flag[session.upload_progress.enabled] = off\n",
		}, "on"},
		"quoted names": {map[string]string{
			"/usr/local/etc/php-fpm.conf":             "[global]\ninclude=etc/php-fpm.d/*.conf\n",
			"/usr/local/etc/php-fpm.d/www.conf":       off,
			"/usr/local/etc/php-fpm.d/zz-docker.conf": "[\"www\"]\nlisten=9000\n['WWW']\nlisten.mode=0660\n",
		}, "off-in-fpm-pool"},
	} {
		c.files["/usr/local/etc/php/php.ini"] = "session.upload_progress.enabled=on\n"
		if s := Evaluate(c.files, true).Settings[UploadProgress]; s.Effective != c.want {
			t.Errorf("%s: upload_progress = %q (%s), want %s", name, s.Effective, s.Why, c.want)
		}
	}
}

func TestOffInPhpIniAndFPMPool(t *testing.T) {
	files := map[string]string{
		"/usr/local/etc/php/php.ini":        "session.upload_progress.enabled=0\n",
		"/usr/local/etc/php-fpm.d/www.conf": "[www]\nphp_admin_flag[session.upload_progress.enabled]=off\n",
	}
	if s := Evaluate(files, true).Settings[UploadProgress]; s.Effective != "off" {
		t.Fatalf("upload_progress = %q (%s), want off", s.Effective, s.Why)
	}
}

func TestCommentedLineIgnored(t *testing.T) {
	files := map[string]string{
		"/etc/php/8.3/apache2/php.ini": ";session.upload_progress.enabled = Off\n",
	}
	r := Evaluate(files, true)
	if got := r.Settings[UploadProgress].Effective; got != "on" {
		t.Fatalf("upload_progress = %q, want on", got)
	}
}

func TestNonPHPPathIgnored(t *testing.T) {
	files := map[string]string{
		"/etc/nginx/conf.d/site.ini": "session.upload_progress.enabled = Off\n",
	}
	r := Evaluate(files, true)
	if got := r.Settings[UploadProgress].Effective; got != "on" {
		t.Fatalf("upload_progress = %q, want on (nginx path is not PHP config)", got)
	}
}

// whichphp cluster uses Reads and ReadsDir to decide which mounts can change the
// settings, so they must agree with what Evaluate reads.
func TestReadsAndReadsDir(t *testing.T) {
	for p, want := range map[string]bool{
		"/usr/local/etc/php/php.ini":                 true,
		"/usr/local/etc/php/conf.d/zz-off.ini":       true,
		"usr/local/etc/php/conf.d/zz-off.ini":        true,
		"/etc/php/8.3/fpm/conf.d/99-x.ini":           true,
		"/etc/php83/conf.d/x.ini":                    true,
		"/etc/php.d/x.ini":                           true,
		"/usr/local/etc/php-fpm.d/www.conf":          true,
		"/etc/php/8.3/fpm/pool.d/www.conf":           true,
		"/usr/local/etc/php/custom.ini":              false, // neither php.ini nor in a scan directory
		"/etc/nginx/conf.d/site.ini":                 false,
		"/var/www/html/.user.ini":                    false,
		"/usr/local/etc/php/conf.d/x.ini/../php.ini": true,
	} {
		if got := Reads(p); got != want {
			t.Errorf("Reads(%q) = %v, want %v", p, got, want)
		}
		if want && !strings.Contains(p, "..") {
			off := "session.upload_progress.enabled = Off\nphp_admin_flag[session.upload_progress.enabled] = off\n"
			if res := Evaluate(map[string]string{p: off}, true); res.Settings[UploadProgress].Effective == "on" {
				t.Errorf("%s: Reads says yes, but Evaluate ignores it", p)
			}
		}
	}
	for dir, want := range map[string]bool{
		"/usr/local/etc/php":              true,
		"/usr/local/etc/php/conf.d":       true,
		"/usr/local/etc/php/conf.d/":      true,
		"/etc/php/8.3/fpm":                true,
		"/etc/php/8.3/apache2/conf.d":     true,
		"/etc/php83/conf.d":               true,
		"/usr/local/etc/php-fpm.d":        true,
		"/etc/nginx/conf.d":               false,
		"/var/www/html":                   false,
		"/usr/local/etc":                  false,
		"/":                               false,
		"/var/run/secrets/kubernetes.io/": false,
	} {
		if got := ReadsDir(dir); got != want {
			t.Errorf("ReadsDir(%q) = %v, want %v", dir, got, want)
		}
	}
}

func TestEvaluateSamePathTwice(t *testing.T) {
	for _, dir := range []string{"usr/local/etc/php", ".x/etc/php"} {
		files := map[string]string{
			dir + "/php.ini":       "session.upload_progress.enabled = On\n",
			"/" + dir + "/php.ini": "session.upload_progress.enabled = Off\n",
		}
		for i := 0; i < 20; i++ {
			res := Evaluate(files, true)
			if got := res.Settings[UploadProgress].Effective; got != "off" {
				t.Fatalf("%s, run %d: got %q, want the absolute path's value, off", dir, i, got)
			}
			if len(res.FilesSeen) != 1 {
				t.Fatalf("FilesSeen = %v", res.FilesSeen)
			}
		}
	}
}

// The layout says which added files PHP reads, from the places the image's own files
// sit in.
func TestLayout(t *testing.T) {
	images := map[string]map[string]string{
		// The official php image: php.ini (none shipped) and conf.d under
		// /usr/local/etc/php, FPM's pools in /usr/local/etc/php-fpm.d.
		"official": {
			"usr/local/etc/php/conf.d/docker-php-ext-sodium.ini": "",
			"/usr/local/etc/php-fpm.conf":                        "",
			"/usr/local/etc/php-fpm.d/www.conf":                  "",
		},
		// Debian's packages: a tree per SAPI.
		"debian": {
			"/etc/php/8.3/fpm/php.ini":               "",
			"/etc/php/8.3/fpm/conf.d/10-opcache.ini": "",
			"/etc/php/8.3/fpm/php-fpm.conf":          "",
			"/etc/php/8.3/fpm/pool.d/www.conf":       "",
		},
		// RHEL: /etc/php.ini with nothing in /etc/php.d.
		"rhel": {"/etc/php.ini": ""},
	}
	for _, c := range []struct {
		image, path string
		want        bool
	}{
		{"official", "/usr/local/etc/php/php.ini", true},
		{"official", "/usr/local/etc/php/conf.d/zz-off.ini", true},
		{"official", "usr/local/etc/php/conf.d/zz-off.ini", true},
		{"official", "/usr/local/etc/php/php.d/zz-off.ini", false},
		{"official", "/usr/local/etc/php.ini", false},
		{"official", "/etc/php/php.ini", false},
		{"official", "/usr/local/etc/php-fpm.d/zz.conf", true},
		{"official", "/usr/local/etc/php-fpm.conf", true},
		{"official", "/usr/local/etc/other-fpm.conf", false},
		{"official", "/etc/php-fpm.d/www.conf", false},
		{"official", "/usr/local/etc/php/conf.d/notes.txt", false},
		{"debian", "/etc/php/8.3/fpm/conf.d/99-off.ini", true},
		{"debian", "/etc/php/8.3/fpm/php.ini", true},
		{"debian", "/etc/php/8.3/apache2/php.ini", false},
		{"debian", "/etc/php/8.3/fpm/pool.d/zz.conf", true},
		{"rhel", "/etc/php.ini", true},
		{"rhel", "/etc/php.d/zz-off.ini", false},
	} {
		if got := NewLayout(images[c.image]).Reads(c.path); got != c.want {
			t.Errorf("%s: Reads(%q) = %v, want %v", c.image, c.path, got, c.want)
		}
	}
	// The files PHP's -c and FPM's -y name when they name the image's own.
	official := NewLayout(images["official"])
	for p, want := range map[string]bool{
		"/usr/local/etc/php/php.ini": true, "/usr/local/etc/php": true, "/usr/local/etc/php/": true,
		"/usr/local/etc/php.ini": false, "usr/local/etc/php/php.ini": false, "/usr/local/etc/php/conf.d/php.ini": false,
	} {
		if got := official.PHPIni(p); got != want {
			t.Errorf("PHPIni(%q) = %v, want %v", p, got, want)
		}
	}
	for p, want := range map[string]bool{
		"/usr/local/etc/php-fpm.conf": true, "/usr/local/etc/php-fpm.d/www.conf": false, "/etc/php-fpm.conf": false, "usr/local/etc/php-fpm.conf": false,
	} {
		if got := official.FPMConfig(p); got != want {
			t.Errorf("FPMConfig(%q) = %v, want %v", p, got, want)
		}
	}
	if NewLayout(nil).Reads("/usr/local/etc/php/php.ini") {
		t.Error("an image without configuration files shows no place PHP reads")
	}
}
