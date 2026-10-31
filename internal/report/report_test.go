package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yusufyildiz34/whichphp/internal/phpini"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

const (
	manifest = "sha256:6985ff1ba36e5fda4a3257bef73c30b04ba657c29cf9cbaafc3f4d4ea0268a51"
	index    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)

func cves(v verdict.Verdict, why string) map[string]verdict.CVEResult {
	return map[string]verdict.CVEResult{
		"CVE-2026-109618": {Verdict: v, Why: why},
		"CVE-2026-109619": {Verdict: v, Why: why},
	}
}

// sample is a pre-fix image pulled from Docker Hub, with one vulnerable source build,
// one backported distro package and one PHP whose status is unknown.
func sample() verdict.Report {
	return verdict.Report{
		Tool: "whichphp", Version: "v0.1.0",
		Image: verdict.Image{
			Input: "php:8.4.26-apache", SourceType: "image",
			Tags: []string{"php:8.4.26-apache"}, RepoDigests: []string{"php@" + index},
			ManifestDigest: manifest, Architecture: "amd64",
		},
		PHP: []verdict.PHP{
			{Name: "libphp", Version: "8.4.26", Source: verdict.SourceUpstream, SAPI: "apache-module",
				Paths: []string{"/usr/lib/apache2/modules/libphp.so"}, CVEs: cves(verdict.Vulnerable, "8.4.26 is older than 8.4.27")},
			{Name: "php8.3-cli", Version: "8.3.6-0ubuntu0.24.04.13", Type: "deb", PURL: "pkg:deb/ubuntu/php8.3-cli@8.3.6-0ubuntu0.24.04.13?arch=amd64",
				Source: verdict.SourceDistro, SAPI: "cli", Paths: []string{"/var/lib/dpkg/status"}, CVEs: cves(verdict.FixedByDistroBackport, "backported")},
			{Name: "php-fpm", Version: "8.4.27", Source: verdict.SourceUpstream, SAPI: "fpm",
				Paths: []string{"/usr/local/sbin/php-fpm"}, CVEs: cves(verdict.Unknown, "no evidence")},
		},
		Settings: map[string]phpini.Setting{phpini.UploadProgress: {Effective: "on", Why: "no php.ini sets it"}},
		Action:   verdict.ActionNeeded,
	}
}

func sarifOf(t *testing.T, r verdict.Report) sarifRun {
	t.Helper()
	var buf bytes.Buffer
	if err := SARIF(&buf, r); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("bad envelope: %+v", log)
	}
	if !strings.Contains(buf.String(), `"results": [`) {
		t.Fatal("results must be an array, never null")
	}
	return log.Runs[0]
}

func TestSARIF(t *testing.T) {
	run := sarifOf(t, sample())
	// A rule per CVE, an "unproven" rule per CVE, and the mitigation rule.
	if len(run.Tool.Driver.Rules) != 5 {
		t.Fatalf("got %d rules", len(run.Tool.Driver.Rules))
	}
	names := map[string]bool{}
	for _, rule := range run.Tool.Driver.Rules {
		if names[rule.Name] {
			t.Errorf("rule name %s is used twice", rule.Name)
		}
		names[rule.Name] = true
	}
	if run.Tool.Driver.Rules[0].Properties["security-severity"] != "9.2" {
		t.Errorf("CVE rules need security-severity: %v", run.Tool.Driver.Rules[0].Properties)
	}
	// 2 CVEs for the vulnerable binary, 2 for the unknown one, 1 for the mitigation;
	// none for the backported package.
	levels := map[string]int{}
	for _, res := range run.Results {
		levels[res.Level]++
		if run.Tool.Driver.Rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("rule index %d doesn't match %s", res.RuleIndex, res.RuleID)
		}
		uri := res.Locations[0].PhysicalLocation.ArtifactLocation.URI
		if uri == "" || strings.HasPrefix(uri, "/") {
			t.Errorf("bad location %q", uri)
		}
		if res.PartialFingerprints["primaryLocationLineHash"] == "" {
			t.Errorf("missing primaryLocationLineHash: %+v", res.PartialFingerprints)
		}
	}
	if len(run.Results) != 5 || levels["error"] != 2 || levels["warning"] != 3 {
		t.Fatalf("got %d results, levels %v", len(run.Results), levels)
	}
	// Uncertain results use a rule without a security-severity, so code scanning
	// doesn't rate an unknown as critical.
	for _, res := range run.Results {
		rule := run.Tool.Driver.Rules[res.RuleIndex]
		_, rated := rule.Properties["security-severity"]
		if res.Level == "warning" && rated {
			t.Errorf("%s (warning) uses rated rule %s", res.RuleID, rule.ID)
		}
		if res.Level == "error" && !rated {
			t.Errorf("%s (error) uses unrated rule %s", res.RuleID, rule.ID)
		}
	}
	if !strings.Contains(run.Tool.Driver.Rules[0].FullDescription.Text, "8.5.12, 8.4.27, 8.3.36 or 8.2.35") {
		t.Errorf("fixed releases missing: %s", run.Tool.Driver.Rules[0].FullDescription.Text)
	}
}

func TestSARIFFingerprints(t *testing.T) {
	// A rebuild, or a per-commit tag of the same image, keeps the same alert.
	a, b := sample(), sample()
	b.Image.ManifestDigest = index
	b.Image.Tags = []string{"php:8.4.26-apache-3f2c1e9"}
	ra, rb := sarifOf(t, a), sarifOf(t, b)
	if ra.Results[0].PartialFingerprints["primaryLocationLineHash"] != rb.Results[0].PartialFingerprints["primaryLocationLineHash"] {
		t.Fatal("a rebuild or a new tag of the same image should keep the same alert")
	}
	// Packages that share a location (the dpkg database) must not share an alert.
	r := sample()
	r.PHP = []verdict.PHP{
		{Name: "php8.2-cli", Type: "deb", Paths: []string{"/var/lib/dpkg/status"}, CVEs: cves(verdict.Vulnerable, "x")},
		{Name: "php8.2-fpm", Type: "deb", Paths: []string{"/var/lib/dpkg/status"}, CVEs: cves(verdict.Vulnerable, "x")},
	}
	run := sarifOf(t, r)
	seen := map[string]bool{}
	for _, res := range run.Results {
		fp := res.RuleID + res.PartialFingerprints["primaryLocationLineHash"]
		if seen[fp] {
			t.Fatalf("two results share fingerprint %s", fp)
		}
		seen[fp] = true
	}
}

func TestSARIFEscapesImageText(t *testing.T) {
	r := sample()
	r.PHP[0].Version = "8.4.26[x](https://evil.example){0}"
	r.PHP[0].Paths = []string{"/opt/my app#1/libphp?.so"}
	run := sarifOf(t, r)
	msg := run.Results[0].Message.Text
	if !strings.Contains(msg, `\[x\]`) || !strings.Contains(msg, "{{0}}") {
		t.Errorf("message not escaped: %s", msg)
	}
	uri := run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	if u, err := url.Parse(uri); err != nil || u.Path != "opt/my app#1/libphp?.so" || u.RawQuery != "" || u.Fragment != "" {
		t.Errorf("uri %q doesn't round-trip: %+v, %v", uri, u, err)
	}
}

func TestSARIFMitigationBranches(t *testing.T) {
	for effective, want := range map[string]string{"on": "warning", "unknown": "note", "off": "", "off-in-fpm-pool": ""} {
		r := sample()
		r.Settings[phpini.UploadProgress] = phpini.Setting{Effective: effective}
		got := ""
		for _, res := range sarifOf(t, r).Results {
			if res.RuleID == mitigationRule {
				got = res.Level
			}
		}
		if got != want {
			t.Errorf("%s: got level %q, want %q", effective, got, want)
		}
	}
}

func TestSARIFEdgeCases(t *testing.T) {
	r := verdict.Report{Image: verdict.Image{Input: "dir:/home/me/site", SourceType: "directory"}, Action: verdict.ActionNoPHP}
	if run := sarifOf(t, r); len(run.Results) != 0 {
		t.Errorf("no PHP should give no results: %+v", run.Results)
	}
	r = sample()
	r.PHP = []verdict.PHP{{Name: "php", Version: "8.1.2", Source: verdict.SourceThirdParty, Provider: "Sury", CVEs: cves(verdict.VulnerableEOL, "EOL")}}
	run := sarifOf(t, r)
	if run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "." || !strings.Contains(run.Results[0].Message.Text, "Sury") {
		t.Errorf("got %+v", run.Results[0])
	}
}

func TestReportsNeverShowLocalPaths(t *testing.T) {
	r := sample()
	r.Image.Input = "/Users/someone/work/php_8.4.26-apache.tar"
	r.Image.Tags, r.Image.RepoDigests = nil, nil
	var s, v bytes.Buffer
	if err := SARIF(&s, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s.String(), "/Users/someone") || !strings.Contains(s.String(), "php_8.4.26-apache.tar") {
		t.Errorf("SARIF leaks the path or loses the name:\n%s", s.String())
	}
	// Without a tag there's no name for a purl, so OpenVEX refuses rather than guess.
	if err := OpenVEX(&v, r, VEXOptions{}); err == nil {
		t.Error("want an error for an image with no name")
	}
}

func vexOf(t *testing.T, r verdict.Report, opt VEXOptions) vexDoc {
	t.Helper()
	oldNow, oldID := now, newID
	now = func() time.Time { return time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC) }
	newID = func() (string, error) { return "urn:uuid:test", nil }
	defer func() { now, newID = oldNow, oldID }()
	var buf bytes.Buffer
	if err := OpenVEX(&buf, r, opt); err != nil {
		t.Fatal(err)
	}
	var doc vexDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, s := range doc.Statements {
		for _, p := range s.Products {
			if !isIRI(p.ID) {
				t.Errorf("product @id %q isn't an absolute IRI", p.ID)
			}
			for _, c := range p.Subcomponents {
				if !isIRI(c.ID) {
					t.Errorf("subcomponent @id %q isn't an absolute IRI", c.ID)
				}
			}
		}
	}
	return doc
}

func isIRI(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && !strings.ContainsAny(s, " \\")
}

func TestOpenVEX(t *testing.T) {
	doc := vexOf(t, sample(), VEXOptions{})
	if doc.Context != "https://openvex.dev/ns/v0.2.0" || doc.Timestamp != "2026-10-31T12:00:00Z" || len(doc.Statements) != 6 ||
		!strings.HasPrefix(doc.Author, "whichphp") {
		t.Fatalf("got %+v", doc)
	}
	status := map[string]int{}
	for _, s := range doc.Statements {
		status[s.Status]++
		if s.Status == "affected" && s.ActionStatement == "" {
			t.Error("affected needs an action statement")
		}
	}
	if status["affected"] != 2 || status["fixed"] != 2 || status["under_investigation"] != 2 {
		t.Fatalf("got %v", status)
	}
	p := doc.Statements[0].Products[0]
	want := "pkg:oci/php@" + strings.Replace(index, ":", "%3A", 1) + "?arch=amd64&repository_url=index.docker.io%2Flibrary%2Fphp&tag=8.4.26-apache"
	if p.ID != want || p.Identifiers["purl"] != want {
		t.Errorf("image purl:\n got %s\nwant %s", p.ID, want)
	}
	if doc.Statements[1].Products[0].Subcomponents[0].ID != "pkg:deb/ubuntu/php8.3-cli@8.3.6-0ubuntu0.24.04.13?arch=amd64" {
		t.Errorf("distro purl: %+v", doc.Statements[1].Products[0])
	}
	if doc.Statements[0].Products[0].Subcomponents[0].ID != "pkg:generic/libphp@8.4.26" {
		t.Errorf("fallback purl: %+v", doc.Statements[0].Products[0])
	}
	if a := vexOf(t, sample(), VEXOptions{Author: "Acme Security"}); a.Author != "Acme Security" {
		t.Errorf("author: %s", a.Author)
	}
}

// Statements that let consumers suppress findings need positive evidence.
func TestOpenVEXOnlyClaimsWhatItCanShow(t *testing.T) {
	r := sample()
	unconfirmed := cves(verdict.FixedByDistroBackport, "no open match (feed coverage not checked)")
	for k, v := range unconfirmed {
		v.Unconfirmed = true
		unconfirmed[k] = v
	}
	r.PHP = []verdict.PHP{
		{Name: "php8.2-cli", Version: "8.2.7-1", Type: "deb", CVEs: unconfirmed},
		{Name: "php", Version: "7.2.34", CVEs: map[string]verdict.CVEResult{
			"CVE-2026-109618": {Verdict: verdict.NotAffected, Why: "older than 7.3.0"},
			"CVE-2026-109619": {Verdict: verdict.VulnerableEOL, Why: "EOL"},
		}},
	}
	got := map[string]string{}
	for _, s := range vexOf(t, r, VEXOptions{}).Statements {
		got[s.Products[0].Subcomponents[0].ID+" "+s.Vulnerability.Name] = s.Status + "/" + s.Justification
	}
	want := map[string]string{
		"pkg:generic/php8.2-cli@8.2.7-1 CVE-2026-109618": "under_investigation/",
		"pkg:generic/php@7.2.34 CVE-2026-109618":         "not_affected/vulnerable_code_not_present",
		"pkg:generic/php@7.2.34 CVE-2026-109619":         "affected/",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q", k, got[k], v)
		}
	}

	r = sample()
	r.PHP, r.Action = nil, verdict.ActionNoPHP
	for _, s := range vexOf(t, r, VEXOptions{}).Statements {
		if s.Status != "under_investigation" {
			t.Errorf("no PHP found must not become %s", s.Status)
		}
	}
}

func TestOpenVEXErrors(t *testing.T) {
	r := verdict.Report{Image: verdict.Image{Input: "dir:.", SourceType: "directory"}}
	if err := OpenVEX(&bytes.Buffer{}, r, VEXOptions{}); err == nil {
		t.Error("a directory has no purl; want an error")
	}
	old := newID
	newID = func() (string, error) { return "", errors.New("no entropy") }
	defer func() { newID = old }()
	if err := OpenVEX(&bytes.Buffer{}, sample(), VEXOptions{}); err == nil {
		t.Error("want the ID error")
	}
}

func TestImagePURL(t *testing.T) {
	img := func(input string, tags, repoDigests []string) verdict.Report {
		return verdict.Report{Image: verdict.Image{Input: input, SourceType: "image", Tags: tags, RepoDigests: repoDigests, ManifestDigest: manifest}}
	}
	m := "sha256%3A6985ff1ba36e5fda4a3257bef73c30b04ba657c29cf9cbaafc3f4d4ea0268a51"
	i := "sha256%3A1111111111111111111111111111111111111111111111111111111111111111"
	cases := []struct {
		name string
		r    verdict.Report
		want string
	}{
		{"pulled from Docker Hub", img("php:8.4-apache", []string{"php:8.4-apache"}, []string{"php@" + index}),
			"pkg:oci/php@" + i + "?repository_url=index.docker.io%2Flibrary%2Fphp&tag=8.4-apache"},
		{"explicit registry", img("registry:GHCR.io/acme/app:1.2", nil, nil),
			"pkg:oci/app@" + m + "?repository_url=ghcr.io%2Facme%2Fapp&tag=1.2"},
		{"tag and digest", img("registry:php:8.4-apache@"+index, nil, nil),
			"pkg:oci/php@" + i + "?repository_url=index.docker.io%2Flibrary%2Fphp&tag=8.4-apache"},
		{"local build has no registry", img("docker:myapp:dev", []string{"myapp:dev"}, nil), "pkg:oci/myapp@" + m + "?tag=dev"},
		{"archive with a tag", img("/tmp/x/php.tar", []string{"php:8.4.26-apache"}, nil), "pkg:oci/php@" + m + "?tag=8.4.26-apache"},
		{"archive without a tag", img("docker-archive:app.tar", nil, nil), ""},
		{"relative path", img("build/app.tar", nil, nil), ""},
		{"windows path", img(`C:\images\app.tar`, nil, nil), ""},
		{"directory", verdict.Report{Image: verdict.Image{Input: "wordpress", SourceType: "directory", ManifestDigest: manifest}}, ""},
		{"bad digest", verdict.Report{Image: verdict.Image{Input: "php", SourceType: "image", Tags: []string{"php:8"}, ManifestDigest: "latest"}}, ""},
	}
	for _, c := range cases {
		if got := imagePURL(c.r); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

func TestImageLabel(t *testing.T) {
	cases := map[string]verdict.Image{
		"php:8.4-apache": {Input: "registry:php:8.4-apache"},
		"app.tar":        {Input: "docker-archive:/home/me/build/app.tar"},
		"site":           {Input: "dir:/home/me/site/"},
		"image.tar":      {Input: `C:\images\image.tar`},
		"php:8.4.26":     {Input: "/tmp/php.tar", Tags: []string{"php:8.4.26"}},
	}
	for want, img := range cases {
		if got := imageLabel(verdict.Report{Image: img}); got != want {
			t.Errorf("%+v: got %q, want %q", img, got, want)
		}
	}
}

func TestPURLEscape(t *testing.T) {
	if got := purlEscape("a-b._~/:%é"); got != "a-b._~%2F%3A%25%C3%A9" {
		t.Errorf("got %s", got)
	}
	if got := phpPURL(verdict.PHP{Name: "PHP"}); got != "pkg:generic/php" {
		t.Errorf("empty version: %s", got)
	}
}

func TestTableCleansImageText(t *testing.T) {
	r := sample()
	r.PHP[0].Paths = []string{"/usr/lib/x\n::warning title=x::fake"}
	r.PHP[0].Name = "::set-output name=action::OK"
	var buf bytes.Buffer
	if err := Table(&buf, r); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, "::") {
			t.Fatalf("image text started a line: %q", line)
		}
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestTableReportsWriteErrors(t *testing.T) {
	if err := Table(failWriter{}, sample()); err == nil {
		t.Fatal("want the write error")
	}
}
