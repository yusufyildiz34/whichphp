package diff

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/yusufyildiz34/whichphp/internal/advisory"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

// assertProvenOK fails when a report reads OK without PHP, or without a fix or not
// affected as the verdict of the image and of every build, for every CVE.
func assertProvenOK(t *testing.T, r verdict.Report) {
	t.Helper()
	if r.Action != verdict.ActionOK {
		return
	}
	if len(r.PHP) == 0 {
		t.Fatal("OK without PHP")
	}
	fix := func(v verdict.Verdict) bool {
		return v == verdict.Fixed || v == verdict.FixedByDistroBackport || v == verdict.FixedByVendorBackport || v == verdict.NotAffected
	}
	for _, cve := range advisory.CVEs {
		if !fix(r.Verdicts[cve]) {
			t.Fatalf("OK with %s %q", cve, r.Verdicts[cve])
		}
		for _, p := range r.PHP {
			if !fix(p.CVEs[cve].Verdict) {
				t.Fatalf("OK with %s %q on %q", cve, p.CVEs[cve].Verdict, p.Name)
			}
		}
	}
	for cve, v := range r.Verdicts {
		if !fix(v) {
			t.Fatalf("OK with %s %q", cve, v)
		}
	}
}

// FuzzParseReport: a report file handed to whichphp diff is untrusted input. Reading it
// must never panic. A report it accepts as OK has PHP and a fix, or not affected, as
// every verdict for every CVE. Two reports it accepts must compare without a panic, to
// a known outcome and an exit code of 0, 1 or 2; "fixed" only for an after image that
// is OK, has PHP and rests on no unconfirmed backport; the JSON must stay valid, and no
// text line may hold a workflow command.
func FuzzParseReport(f *testing.F) {
	before := `{"tool":"whichphp","version":"v0.3.0","image":{"input":"php:8.4.26-apache","sourceType":"image","tags":["php:8.4.26-apache"],"manifestDigest":"sha256:6985ff1ba36e5fda4a3257bef73c30b04ba657c29cf9cbaafc3f4d4ea0268a51","architecture":"amd64","created":"2026-10-01T08:12:00Z"},` +
		`"distro":{"id":"debian","version":"13","support":"supported"},"php":[{"name":"libphp","version":"8.4.26","type":"binary","source":"upstream-build","sapi":"apache-module","paths":["/usr/lib/apache2/modules/libphp.so"],` +
		`"cves":{"CVE-2026-109618":{"verdict":"VULNERABLE","why":"x","grypeMatched":false},"CVE-2026-109619":{"verdict":"VULNERABLE","why":"x","grypeMatched":false}}},` +
		`{"name":"php8.3-fpm","version":"8.3.6-0ubuntu0.24.04.13","source":"distro","sapi":"fpm","cves":{"CVE-2026-109618":{"verdict":"FIXED_BY_DISTRO_BACKPORT"}}}],` +
		`"verdicts":{"CVE-2026-109618":"VULNERABLE","CVE-2026-109619":"VULNERABLE"},"settings":{"session.upload_progress.enabled":{"effective":"on","why":"default"}},"data":{"grypeUsed":true,"feedCoverageChecked":false},"action":"ACTION_NEEDED","notes":["n"]}`
	fixed := `"cves":{"CVE-2026-109618":{"verdict":"FIXED"},"CVE-2026-109619":{"verdict":"FIXED"}}`
	after := `{"tool":"whichphp","version":"v0.4.0","image":{"input":"/tmp/app.tar","architecture":"arm64"},"php":[{"name":"libphp","version":"8.4.27","sapi":"apache-module",` + fixed + `},` +
		`{"name":"php8.4-fpm","version":"8.4.27-1","sapi":"fpm",` + fixed + `},{"name":"::warning::x","version":"##[group]","sapi":"cli",` +
		`"cves":{"CVE-2026-109618":{"verdict":"NOT_AFFECTED"},"CVE-2026-109619":{"verdict":"FIXED"}," ::debug::z":{"verdict":"FIXED"}}}],` +
		`"verdicts":{"CVE-2026-109618":"FIXED","CVE-2026-109619":"FIXED","::error::y":"FIXED"},"settings":{"session.upload_progress.enabled":{"effective":"off"}},"action":"OK"}`
	f.Add([]byte(before), []byte(after))
	f.Add([]byte(before), []byte(`{"tool":"whichphp","version":"v0.4.0","image":{},"php":[{"name":"php8.3-fpm","version":"8.3.6-0ubuntu0.24.04.13","source":"distro","sapi":"fpm",`+
		`"cves":{"CVE-2026-109618":{"verdict":"FIXED_BY_DISTRO_BACKPORT","unconfirmed":true},"CVE-2026-109619":{"verdict":"FIXED_BY_DISTRO_BACKPORT","unconfirmed":true}}}],`+
		`"verdicts":{"CVE-2026-109618":"FIXED_BY_DISTRO_BACKPORT","CVE-2026-109619":"FIXED_BY_DISTRO_BACKPORT"},"action":"OK"}`))
	f.Add([]byte(after), []byte(before))
	f.Add([]byte(`{"tool":"whichphp","image":{},"php":null,"action":"NO_PHP"}`), []byte("\xef\xbb\xbf"+before))
	f.Add([]byte(`{"tool":"whichphp","image":{},"php":[{},{}],"action":"UNKNOWN","verdicts":{"":""}}`), []byte(`{"tool":"whichphp","image":{"tags":[":"]},"php":[{"sapi":"cli",`+fixed+`}],"verdicts":{"CVE-2026-109618":"NOT_AFFECTED","CVE-2026-109619":"FIXED"},"action":"OK"}`))
	f.Fuzz(func(t *testing.T, a, b []byte) {
		before, err := ParseReport(a)
		if err != nil {
			return
		}
		after, err := ParseReport(b)
		if err != nil {
			return
		}
		for _, r := range []verdict.Report{before, after} {
			assertProvenOK(t, r)
		}
		for _, opt := range []Options{{}, {FailOnMitigation: true}} {
			d := Compare(before, after, opt)
			if summaries[d.Outcome] == "" || d.Summary != summaries[d.Outcome] {
				t.Fatalf("unknown outcome %q (%q)", d.Outcome, d.Summary)
			}
			if code := d.ExitCode(); code < 0 || code > 2 {
				t.Fatalf("exit code %d", code)
			}
			if d.Outcome == Fixed {
				if d.Action.After != string(verdict.ActionOK) || len(after.PHP) == 0 {
					t.Fatalf("fixed, but the after image is %s with %d PHP builds", d.Action.After, len(after.PHP))
				}
				for _, p := range after.PHP {
					for _, r := range p.CVEs {
						if r.Unconfirmed && r.Verdict == verdict.FixedByDistroBackport {
							t.Fatal("fixed on an unconfirmed backport")
						}
					}
				}
			}
			var js, tb bytes.Buffer
			if err := JSON(&js, d); err != nil || !json.Valid(js.Bytes()) {
				t.Fatalf("JSON: %v", err)
			}
			if err := Table(&tb, d); err != nil {
				t.Fatal(err)
			}
			assertSafeForCI(t, tb.String())
		}
	})
}
