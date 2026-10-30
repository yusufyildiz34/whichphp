package phpini

import "testing"

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
