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
