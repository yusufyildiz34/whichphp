package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
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
	// CycloneDX doesn't need a purl: the archive's base name names it.
	bom, raw := cdxOf(t, r)
	if strings.Contains(raw, "/Users/someone") || bom.Metadata.Component.Name != "php_8.4.26-apache.tar" ||
		bom.Metadata.Component.Type != "container" || bom.Metadata.Component.PURL != "" {
		t.Errorf("CycloneDX leaks the path or misnames the image: %+v", bom.Metadata.Component)
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
		// A packager's backport rests on its own published release, which is positive
		// evidence.
		{Name: "php7.4-fpm", Version: "1:7.4.33-31", Type: "deb", Source: verdict.SourceThirdParty, Provider: "Sury",
			CVEs: cves(verdict.FixedByVendorBackport, "Sury backported the fix into 1:7.4.33-31")},
		{Name: "php7.4-cli", Version: "1:7.4.33-20", Type: "deb", Source: verdict.SourceThirdParty, Provider: "Sury",
			CVEs: cves(verdict.NeedsVendorConfirmation, "no data")},
	}
	got := map[string]string{}
	for _, s := range vexOf(t, r, VEXOptions{}).Statements {
		got[s.Products[0].Subcomponents[0].ID+" "+s.Vulnerability.Name] = s.Status + "/" + s.Justification
	}
	want := map[string]string{
		"pkg:generic/php8.2-cli@8.2.7-1 CVE-2026-109618":       "under_investigation/",
		"pkg:generic/php@7.2.34 CVE-2026-109618":               "not_affected/vulnerable_code_not_present",
		"pkg:generic/php@7.2.34 CVE-2026-109619":               "affected/",
		"pkg:generic/php7.4-fpm@1%3A7.4.33-31 CVE-2026-109619": "fixed/",
		"pkg:generic/php7.4-cli@1%3A7.4.33-20 CVE-2026-109619": "under_investigation/",
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

const testSerial = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"

// cdxOf returns the CycloneDX BOM for r, parsed and as written, with a fixed clock
// and serial number.
func cdxOf(t *testing.T, r verdict.Report) (cdxBOM, string) {
	t.Helper()
	oldNow, oldID := now, newID
	now = func() time.Time { return time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC) }
	newID = func() (string, error) { return testSerial, nil }
	defer func() { now, newID = oldNow, oldID }()
	var buf bytes.Buffer
	if err := CycloneDX(&buf, r, VEXOptions{}); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Fatalf("not valid JSON:\n%s", buf.String())
	}
	var bom cdxBOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	if err := checkRefs(bom); err != nil {
		t.Fatal(err)
	}
	return bom, buf.String()
}

// checkRefs reports a bom-ref that is empty or used twice, and an affects ref that
// names nothing in the BOM.
func checkRefs(bom cdxBOM) error {
	seen := map[string]bool{}
	targets := map[string]bool{}
	add := func(ref string, target bool) error {
		if ref == "" || seen[ref] {
			return fmt.Errorf("bom-ref %q is empty or used twice", ref)
		}
		seen[ref], targets[ref] = true, target
		return nil
	}
	if err := add(bom.Metadata.Component.BOMRef, true); err != nil {
		return err
	}
	for _, c := range bom.Components {
		if err := add(c.BOMRef, true); err != nil {
			return err
		}
	}
	for _, v := range bom.Vulnerabilities {
		if err := add(v.BOMRef, false); err != nil {
			return err
		}
	}
	for _, v := range bom.Vulnerabilities {
		if len(v.Affects) == 0 {
			return fmt.Errorf("%s affects nothing", v.BOMRef)
		}
		for _, a := range v.Affects {
			if !targets[a.Ref] {
				return fmt.Errorf("%s affects %q, which isn't a component", v.BOMRef, a.Ref)
			}
		}
	}
	return nil
}

func TestCycloneDX(t *testing.T) {
	bom, raw := cdxOf(t, sample())
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.6" || bom.Version != 1 || bom.SerialNumber != testSerial ||
		bom.Schema != "http://cyclonedx.org/schema/bom-1.6.schema.json" || bom.Metadata.Timestamp != "2026-10-31T12:00:00Z" {
		t.Fatalf("bad envelope:\n%s", raw)
	}
	if tools := bom.Metadata.Tools.Components; len(tools) != 1 || tools[0].Name != "whichphp" || tools[0].Version != "v0.1.0" {
		t.Errorf("tools: %+v", tools)
	}
	// The image is named by the same purl OpenVEX uses for its product.
	subject := bom.Metadata.Component
	want := "pkg:oci/php@" + strings.Replace(index, ":", "%3A", 1) + "?arch=amd64&repository_url=index.docker.io%2Flibrary%2Fphp&tag=8.4.26-apache"
	if subject.Type != "container" || subject.Name != "php:8.4.26-apache" || subject.PURL != want || subject.BOMRef != want ||
		len(subject.Hashes) != 1 || subject.Hashes[0] != (cdxHash{Alg: "SHA-256", Content: strings.TrimPrefix(manifest, "sha256:")}) {
		t.Errorf("subject: %+v", subject)
	}
	if vexOf(t, sample(), VEXOptions{}).Statements[0].Products[0].ID != subject.PURL {
		t.Error("CycloneDX and OpenVEX name the image differently")
	}

	// Components are sorted by purl, and use the purls OpenVEX uses.
	var purls []string
	for _, c := range bom.Components {
		purls = append(purls, c.PURL)
		if c.Type != "application" || c.BOMRef != c.PURL {
			t.Errorf("component: %+v", c)
		}
	}
	if got := strings.Join(purls, " "); got != "pkg:deb/ubuntu/php8.3-cli@8.3.6-0ubuntu0.24.04.13?arch=amd64 pkg:generic/libphp@8.4.26 pkg:generic/php-fpm@8.4.27" {
		t.Errorf("components: %s", got)
	}
	if got := bom.Components[1].Properties; len(got) != 2 || got[0] != (cdxProperty{Name: "whichphp:sapi", Value: "apache-module"}) ||
		got[1] != (cdxProperty{Name: "whichphp:source", Value: verdict.SourceUpstream}) {
		t.Errorf("properties: %+v", got)
	}

	// The three builds are in three states, so each CVE is listed once per build.
	if len(bom.Vulnerabilities) != 6 {
		t.Fatalf("got %d vulnerabilities", len(bom.Vulnerabilities))
	}
	states := map[string]int{}
	for i, v := range bom.Vulnerabilities {
		states[v.Analysis.State]++
		wantID := "CVE-2026-109618"
		if i >= 3 {
			wantID = "CVE-2026-109619"
		}
		if v.ID != wantID || v.Source != (cdxSource{Name: "NVD", URL: "https://nvd.nist.gov/vuln/detail/" + wantID}) {
			t.Errorf("vulnerability %d: %s, %+v", i, v.ID, v.Source)
		}
		if len(v.Ratings) != 1 || v.Ratings[0] != (cdxRating{Source: cdxSource{Name: "php.net"}, Score: 9.2, Severity: "critical", Method: "CVSSv4"}) {
			t.Errorf("ratings: %+v", v.Ratings)
		}
		if len(v.Affects) != 1 || v.Affects[0].Ref != bom.Components[i%3].BOMRef || v.BOMRef != v.ID+"/"+bom.Components[i%3].BOMRef {
			t.Errorf("vulnerability %s: bom-ref %s, affects %+v", v.ID, v.BOMRef, v.Affects)
		}
	}
	if states["exploitable"] != 2 || states["resolved"] != 2 || states["in_triage"] != 2 {
		t.Errorf("states: %v", states)
	}
	if d := bom.Vulnerabilities[1].Analysis.Detail; d != "libphp 8.4.26 (upstream-build, apache-module): VULNERABLE: 8.4.26 is older than 8.4.27" {
		t.Errorf("detail: %s", d)
	}
}

// Every verdict maps to the analysis state its OpenVEX status calls for.
func TestCycloneDXAnalysis(t *testing.T) {
	cases := []struct {
		verdict       verdict.Verdict
		unconfirmed   bool
		state, justif string
		response      []string
	}{
		{verdict.Fixed, false, "resolved", "", nil},
		{verdict.FixedByVendorBackport, false, "resolved", "", nil},
		{verdict.FixedByDistroBackport, false, "resolved", "", nil},
		{verdict.FixedByDistroBackport, true, "in_triage", "", nil},
		{verdict.NotAffected, false, "not_affected", "code_not_present", nil},
		{verdict.Vulnerable, false, "exploitable", "", []string{"update"}},
		{verdict.VulnerableEOL, false, "exploitable", "", []string{"update"}},
		{verdict.NeedsVendorConfirmation, false, "in_triage", "", nil},
		{verdict.Unknown, false, "in_triage", "", nil},
		{verdict.DataStale, false, "in_triage", "", nil},
	}
	for _, c := range cases {
		res := cves(c.verdict, "because "+string(c.verdict))
		for k, v := range res {
			v.Unconfirmed = c.unconfirmed
			res[k] = v
		}
		r := sample()
		r.PHP = []verdict.PHP{{Name: "php7.4-fpm", Version: "1:7.4.33-31", Type: "deb", Source: verdict.SourceThirdParty,
			Provider: "Sury", SAPI: "fpm", CVEs: res}}
		bom, _ := cdxOf(t, r)
		if len(bom.Vulnerabilities) != 2 {
			t.Fatalf("%s: got %d vulnerabilities", c.verdict, len(bom.Vulnerabilities))
		}
		for _, v := range bom.Vulnerabilities {
			a := v.Analysis
			if a.State != c.state || a.Justification != c.justif || strings.Join(a.Response, ",") != strings.Join(c.response, ",") ||
				a.Detail != "php7.4-fpm 1:7.4.33-31 (third-party, fpm): "+string(c.verdict)+": because "+string(c.verdict) {
				t.Errorf("%s (unconfirmed %v): got %+v", c.verdict, c.unconfirmed, a)
			}
			if len(v.Affects) != 1 || v.Affects[0].Ref != "pkg:generic/php7.4-fpm@1%3A7.4.33-31" || v.BOMRef != v.ID {
				t.Errorf("%s: bom-ref %s, affects %+v", c.verdict, v.BOMRef, v.Affects)
			}
		}
		if p := bom.Components[0].Properties; len(p) != 3 || p[0] != (cdxProperty{Name: "whichphp:provider", Value: "Sury"}) {
			t.Errorf("properties: %+v", p)
		}
	}
}

// Builds in the same state share an entry; builds in different states don't.
func TestCycloneDXSplitsDifferingStates(t *testing.T) {
	r := sample()
	r.PHP = []verdict.PHP{
		{Name: "php", Version: "8.4.26", CVEs: cves(verdict.Vulnerable, "older than 8.4.27")},
		{Name: "php", Version: "7.2.34", CVEs: map[string]verdict.CVEResult{
			"CVE-2026-109618": {Verdict: verdict.NotAffected, Why: "older than 7.3.0"},
			"CVE-2026-109619": {Verdict: verdict.VulnerableEOL, Why: "EOL"},
		}},
	}
	bom, _ := cdxOf(t, r)
	var got []string
	for _, v := range bom.Vulnerabilities {
		var affects []string
		for _, a := range v.Affects {
			affects = append(affects, a.Ref)
		}
		got = append(got, v.BOMRef+" "+v.Analysis.State+" "+strings.Join(affects, ","))
	}
	want := []string{
		"CVE-2026-109618/pkg:generic/php@7.2.34 not_affected pkg:generic/php@7.2.34",
		"CVE-2026-109618/pkg:generic/php@8.4.26 exploitable pkg:generic/php@8.4.26",
		"CVE-2026-109619 exploitable pkg:generic/php@7.2.34,pkg:generic/php@8.4.26",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// A shared entry gives each build's reason.
	if d := bom.Vulnerabilities[2].Analysis.Detail; d != "php 7.2.34 (, ): VULNERABLE_EOL: EOL\nphp 8.4.26 (, ): VULNERABLE: older than 8.4.27" {
		t.Errorf("detail: %q", d)
	}
}

func TestCycloneDXNoPHP(t *testing.T) {
	r := sample()
	r.PHP, r.Action = nil, verdict.ActionNoPHP
	bom, raw := cdxOf(t, r)
	if !strings.Contains(raw, `"components": []`) || len(bom.Vulnerabilities) != 2 {
		t.Fatalf("got:\n%s", raw)
	}
	// The same words as OpenVEX, and never a state that would hide a finding.
	note := vexOf(t, r, VEXOptions{}).Statements[0].StatusNotes
	for _, v := range bom.Vulnerabilities {
		if v.Analysis.State != "in_triage" || v.Analysis.Detail != note || v.BOMRef != v.ID ||
			len(v.Affects) != 1 || v.Affects[0].Ref != bom.Metadata.Component.BOMRef {
			t.Errorf("no PHP found: %+v", v)
		}
	}
}

func TestCycloneDXDirectory(t *testing.T) {
	r := verdict.Report{
		Version: "v0.3.0",
		Image:   verdict.Image{Input: "dir:/home/me/site/", SourceType: "directory"},
		PHP: []verdict.PHP{{Name: "php", Version: "8.4.27", Source: verdict.SourceUpstream, SAPI: "cli",
			Paths: []string{"/usr/local/bin/php"}, CVEs: cves(verdict.Fixed, "8.4.27 is fixed")}},
		Action: verdict.ActionOK,
	}
	bom, raw := cdxOf(t, r)
	if s := bom.Metadata.Component; s.Type != "file" || s.Name != "site" || s.BOMRef != "site" || s.PURL != "" || s.Hashes != nil {
		t.Errorf("subject: %+v", s)
	}
	if strings.Contains(raw, "/home/me") {
		t.Errorf("the BOM leaks a local path:\n%s", raw)
	}
	if len(bom.Vulnerabilities) != 2 || bom.Vulnerabilities[0].Analysis.State != "resolved" {
		t.Errorf("vulnerabilities: %+v", bom.Vulnerabilities)
	}
	r.PHP = nil
	bom, _ = cdxOf(t, r)
	if d := bom.Vulnerabilities[0].Analysis.Detail; !strings.HasPrefix(d, "whichphp found no PHP in this directory.") {
		t.Errorf("detail: %s", d)
	}
}

// An image without a digest, such as an archive without one, is named only by its
// tag. OpenVEX refuses it; CycloneDX describes it, and its analyses keep their states,
// since they are about the PHP components of this BOM.
func TestCycloneDXImageWithoutDigest(t *testing.T) {
	r := sample()
	r.Image.ManifestDigest, r.Image.RepoDigests = "", nil
	r.PHP = []verdict.PHP{{Name: "php", Version: "8.4.27", Source: verdict.SourceUpstream, SAPI: "cli", CVEs: cves(verdict.Fixed, "8.4.27 is fixed")}}
	r.Action = verdict.ActionOK
	if err := OpenVEX(io.Discard, r, VEXOptions{}); err == nil {
		t.Error("OpenVEX named an image without a digest")
	}
	bom, _ := cdxOf(t, r)
	if s := bom.Metadata.Component; s.Type != "container" || s.Name != "php:8.4.26-apache" || s.PURL != "" || s.Hashes != nil || s.BOMRef != s.Name {
		t.Errorf("subject: %+v", s)
	}
	for _, v := range bom.Vulnerabilities {
		if v.Analysis.State != "resolved" || len(v.Affects) != 1 || v.Affects[0].Ref != "pkg:generic/php@8.4.27" {
			t.Errorf("vulnerability: %+v", v)
		}
	}
}

// purls and names come from the image, so bom-refs built from them can collide.
func TestCycloneDXBOMRefsStayUnique(t *testing.T) {
	r := sample()
	img := imagePURL(r)
	// Once with every build in one state (an entry per CVE), once in different states
	// (an entry per build).
	for _, shared := range []bool{true, false} {
		v := func(own verdict.Verdict) verdict.Verdict {
			if shared {
				return verdict.Vulnerable
			}
			return own
		}
		r.PHP = []verdict.PHP{
			{Name: "php", Version: "8.4.26", CVEs: cves(v(verdict.Vulnerable), "a")},
			{Name: "php", Version: "8.4.26", Type: "binary", CVEs: cves(v(verdict.Fixed), "b")},
			{Name: "php", PURL: "pkg:generic/php@8.4.26#2", CVEs: cves(v(verdict.Unknown), "c")},
			{Name: "image", PURL: img, CVEs: cves(v(verdict.NotAffected), "d")},
			{Name: "cve", PURL: "CVE-2026-109618", CVEs: cves(v(verdict.DataStale), "e")},
			{Name: "cve", PURL: "CVE-2026-109619/pkg:generic/php@8.4.26", CVEs: cves(v(verdict.Vulnerable), "f")},
			// Different here, but both written as U+FFFD.
			{Name: "bad", PURL: "\xc1", CVEs: cves(v(verdict.Unknown), "g")},
			{Name: "bad", PURL: "\xd5", CVEs: cves(v(verdict.Unknown), "h")},
		}
		bom, _ := cdxOf(t, r) // checks that every bom-ref is unique
		if len(bom.Components) != len(r.PHP) || bom.Metadata.Component.BOMRef != img {
			t.Errorf("got %d components, subject %s", len(bom.Components), bom.Metadata.Component.BOMRef)
		}
	}
}

func TestCycloneDXIsDeterministic(t *testing.T) {
	r := sample()
	_, a := cdxOf(t, r)
	for i, j := 0, len(r.PHP)-1; i < j; i, j = i+1, j-1 {
		r.PHP[i], r.PHP[j] = r.PHP[j], r.PHP[i]
	}
	if _, b := cdxOf(t, r); a != b {
		t.Errorf("the order of PHP builds changed the BOM:\n%s\n---\n%s", a, b)
	}
}

func TestCycloneDXErrors(t *testing.T) {
	// The real serial number is a random (version 4) UUID, as CycloneDX requires.
	var buf bytes.Buffer
	if err := CycloneDX(&buf, sample(), VEXOptions{}); err != nil {
		t.Fatal(err)
	}
	var bom cdxBOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(bom.SerialNumber) {
		t.Errorf("serial number %q", bom.SerialNumber)
	}
	if err := CycloneDX(failWriter{}, sample(), VEXOptions{}); err == nil {
		t.Error("want the write error")
	}
	old := newID
	newID = func() (string, error) { return "", errors.New("no entropy") }
	defer func() { newID = old }()
	if err := CycloneDX(&bytes.Buffer{}, sample(), VEXOptions{}); err == nil {
		t.Error("want the serial number error")
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

func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"libphp":              "libphp",
		"::warning::x":        "?:warning::x",
		" ::warning::x":       " ?:warning::x",
		"\u00a0\u3000::x":     "\u00a0\u3000?:x",
		"a::b":                "a::b",
		"8.4.26##[add-mask]x": "8.4.26#?[add-mask]x",
		"x\n::y":              "x?::y",
		"\u2028::y":           "?::y",
	} {
		if got := clean(in); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
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

func TestTableShowsTheBaseImage(t *testing.T) {
	r := sample()
	var out strings.Builder
	if err := Table(&out, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "Base:") {
		t.Fatal("no base, but a Base line")
	}
	for base, want := range map[*verdict.BaseImage]string{
		{Image: "php", Tag: "8.4.26-apache-trixie", PHPVersion: "8.4.26"}: "Base:    php:8.4.26-apache-trixie (from the image's environment)",
		{Image: "php", PHPVersion: "8.4.26"}:                              "Base:    php with PHP 8.4.26 (from the image's environment)",
	} {
		r.Image.Base = base
		out.Reset()
		if err := Table(&out, r); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), want) {
			t.Errorf("want %q in:\n%s", want, out.String())
		}
	}
}

func TestCycloneDXAuthor(t *testing.T) {
	for author, want := range map[string]string{"": "", "  ": "", "Acme Security": "Acme Security"} {
		var buf bytes.Buffer
		if err := CycloneDX(&buf, sample(), VEXOptions{Author: author}); err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Metadata struct {
				Authors []struct{ Name string } `json:"authors"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		got := ""
		if len(doc.Metadata.Authors) == 1 {
			got = doc.Metadata.Authors[0].Name
		}
		if got != want || len(doc.Metadata.Authors) > 1 {
			t.Errorf("author %q: got %+v", author, doc.Metadata.Authors)
		}
	}
}
