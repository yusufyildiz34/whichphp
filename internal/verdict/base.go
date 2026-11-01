package verdict

import (
	"fmt"
	"strings"

	"github.com/yusufyildiz34/whichphp/internal/advisory"
	"github.com/yusufyildiz34/whichphp/internal/phpver"
	"github.com/yusufyildiz34/whichphp/internal/syftjson"
)

// BaseImage is the image this one was built on, as far as its configuration shows.
// Images built FROM an official php image inherit its environment, so PHP_VERSION and
// the php.net download URL name the PHP the base shipped, even in an app image.
type BaseImage struct {
	// Image is the base image's repository, "php" or "bitnami/php-fpm".
	Image string `json:"image"`
	// Tag is the base's tag as whichphp reconstructs it, "8.4.26-apache-trixie". It is
	// the version the base had when this image was built, not one to pull today.
	Tag        string `json:"tag,omitempty"`
	PHPVersion string `json:"phpVersion"`
	// Variant is "apache", "fpm" or "" when the image doesn't show it (cli or zts).
	Variant  string `json:"variant,omitempty"`
	OS       string `json:"os,omitempty"`
	Evidence string `json:"evidence"`
}

// Debian's release names, as the official php images' tags use them.
var debianNames = map[string]string{"9": "stretch", "10": "buster", "11": "bullseye", "12": "bookworm", "13": "trixie", "14": "forky"}

// findBase reads the base image from the image config's environment.
func findBase(cfg *syftjson.ImageConfig, distro syftjson.Distro, php []PHP) *BaseImage {
	if version, ok := cfg.EnvValue("PHP_VERSION"); ok {
		url, _ := cfg.EnvValue("PHP_URL")
		ini, _ := cfg.EnvValue("PHP_INI_DIR")
		if _, parsed := phpver.Parse(version); !parsed || ini != "/usr/local/etc/php" || !strings.HasPrefix(url, "https://www.php.net/distributions/") {
			return nil
		}
		b := &BaseImage{Image: "php", PHPVersion: version, Evidence: "PHP_VERSION, PHP_URL and PHP_INI_DIR in the image's environment"}
		if _, ok := cfg.EnvValue("APACHE_CONFDIR"); ok {
			b.Variant = "apache"
			b.Evidence += ", APACHE_CONFDIR for the apache variant"
		} else if hasPath(php, "/usr/local/sbin/php-fpm") {
			b.Variant = "fpm"
			b.Evidence += ", /usr/local/sbin/php-fpm for the fpm variant"
		}
		switch distro.ID {
		case "debian":
			b.OS = debianNames[advisory.NormalizeRelease("debian", distro.VersionID)]
		case "alpine":
			if rel := advisory.NormalizeRelease("alpine", distro.VersionID); rel != "" {
				b.OS = "alpine" + rel
			}
		}
		parts := []string{version}
		for _, p := range []string{b.Variant, b.OS} {
			if p != "" {
				parts = append(parts, p)
			}
		}
		if b.Variant != "" && b.OS != "" {
			b.Tag = strings.Join(parts, "-")
		}
		return b
	}
	if app, ok := cfg.EnvValue("BITNAMI_APP_NAME"); ok && (app == "php" || app == "php-fpm") {
		version, _ := cfg.EnvValue("APP_VERSION")
		if _, parsed := phpver.Parse(version); !parsed {
			return nil
		}
		return &BaseImage{Image: "bitnami/" + app, Tag: version, PHPVersion: version,
			Evidence: "BITNAMI_APP_NAME and APP_VERSION in the image's environment"}
	}
	return nil
}

func hasPath(php []PHP, path string) bool {
	for _, p := range php {
		for _, q := range p.Paths {
			if q == path {
				return true
			}
		}
	}
	return false
}

// baseAdvice says what to rebuild on when the PHP the base shipped, still in the image
// under /usr/local, is vulnerable. Another vulnerable PHP in the image (a distro package)
// isn't fixed by a new base, so it gets no advice here.
func baseAdvice(b *BaseImage, php []PHP) string {
	if b == nil || b.Image != "php" {
		return ""
	}
	v, ok := phpver.Parse(b.PHPVersion)
	if !ok || !baseVulnerable(v, php) {
		return ""
	}
	br := v.Branch()
	fixed, supported := advisory.Fixed[br]
	switch {
	case !supported && phpver.Less([3]int{br[0], br[1], 0}, [3]int{8, 2, 0}):
		return fmt.Sprintf("This image was built on the official php image with PHP %s. PHP %d.%d gets no upstream fix: move it to a php image of a supported branch (8.2 or later) and rebuild.",
			b.PHPVersion, br[0], br[1])
	case !supported:
		return ""
	}
	// The floating tags: the official image stops building old Debian and Alpine
	// releases, so a tag with the base's own release may never get the fix.
	tag := fmt.Sprintf("%d.%d", br[0], br[1])
	if b.Variant != "" {
		tag += "-" + b.Variant
	}
	if strings.HasPrefix(b.OS, "alpine") {
		tag += "-alpine"
	}
	image := "the current php:" + tag
	if b.Variant == "" {
		image = fmt.Sprintf("a current php:%s image of the same variant (cli or zts)", tag)
	}
	return fmt.Sprintf("This image was built on the official php image with PHP %s. Rebuild it on %s, which has %s or later.",
		b.PHPVersion, image, phpver.FormatTriple(fixed))
}

// baseVulnerable reports whether the image still holds the base's own PHP, an upstream
// build under /usr/local or the official image's Apache module at the base's version,
// and it is vulnerable.
func baseVulnerable(v phpver.Version, php []PHP) bool {
	for _, p := range php {
		pv, ok := phpver.Parse(p.Version)
		if p.Source != SourceUpstream || !ok || pv.Triple() != v.Triple() || !fromBase(p.Paths) {
			continue
		}
		for _, res := range p.CVEs {
			if res.Verdict.IsVulnerable() {
				return true
			}
		}
	}
	return false
}

func fromBase(paths []string) bool {
	for _, path := range paths {
		if strings.HasPrefix(path, "/usr/local/") || path == "/usr/lib/apache2/modules/libphp.so" {
			return true
		}
	}
	return false
}
