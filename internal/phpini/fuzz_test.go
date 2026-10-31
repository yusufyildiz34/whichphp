package phpini

import (
	"reflect"
	"testing"
)

// FuzzEvaluate: php.ini and FPM pool files come from the image. Reading them must
// never panic, every setting must get one of the documented values, and the result
// must not depend on the order the files are read in (Go randomizes map order, so
// evaluating the same files twice checks that).
func FuzzEvaluate(f *testing.F) {
	f.Add("/usr/local/etc/php/php.ini", "session.upload_progress.enabled = Off\n", "/usr/local/etc/php/conf.d/x.ini", "session.upload_progress.enabled = On\n")
	f.Add("/etc/php/8.3/fpm/pool.d/www.conf", "[www]\nphp_admin_flag[session.upload_progress.enabled] = off\n", "/etc/php/8.3/fpm/php.ini", "session.upload_progress.enabled=1\n")
	f.Add("/etc/php/8.3/cli/php.ini", "[PHP]\n;comment\nsession.upload_progress.enabled=\"1\"\n", "/etc/php/8.3/cli/conf.d/20-x.ini", "[PATH=/x]\nsession.upload_progress.enabled=0\n")
	f.Fuzz(func(t *testing.T, path1, contents1, path2, contents2 string) {
		files := map[string]string{path1: contents1, path2: contents2}
		res := Evaluate(files, true)
		for name, s := range res.Settings {
			switch s.Effective {
			case "on", "off", "off-in-fpm-pool", "unknown":
			default:
				t.Fatalf("%s: unexpected value %q", name, s.Effective)
			}
		}
		for i := 0; i < 4; i++ {
			if again := Evaluate(files, true); !reflect.DeepEqual(again, res) {
				t.Fatalf("the result depends on file order:\n%+v\n%+v", res, again)
			}
		}
	})
}
