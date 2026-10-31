package index

import (
	"bytes"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const testSite = "https://example.github.io/whichphp/"

var utcRE = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$`)

// checkAtom fails the test unless b is a well-formed Atom document that uses only
// Atom elements, only the attributes the writer emits, text content and links back
// to the site. The publish job applies the same rules before serving a feed.
func checkAtom(t testing.TB, b []byte) (entries int) {
	t.Helper()
	if bytes.Contains(b, []byte("<!DOCTYPE")) || bytes.Contains(b, []byte("<!ENTITY")) {
		t.Fatalf("feed declares a DTD or entity")
	}
	dec := xml.NewDecoder(bytes.NewReader(b))
	depth := 0
	var stack []string
	var text strings.Builder
	ids := map[string]bool{}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("feed isn't well-formed XML: %v\n%s", err, b)
		}
		switch el := tok.(type) {
		case xml.StartElement:
			if el.Name.Space != "http://www.w3.org/2005/Atom" {
				t.Fatalf("non-Atom element %v", el.Name)
			}
			if depth == 0 && el.Name.Local != "feed" {
				t.Fatalf("root element is %s", el.Name.Local)
			}
			if el.Name.Local == "entry" {
				entries++
			}
			for _, a := range el.Attr {
				switch {
				case a.Name.Space == "xmlns" || (a.Name.Space == "" && a.Name.Local == "xmlns"):
				case a.Name.Space != "":
					t.Fatalf("namespaced attribute %v", a.Name)
				case a.Name.Local == "href":
					if !strings.HasPrefix(a.Value, testSite) {
						t.Fatalf("link outside the site: %q", a.Value)
					}
				case a.Name.Local == "type" && el.Name.Local == "content":
					if a.Value != "text" {
						t.Fatalf("content type %q", a.Value)
					}
				case a.Name.Local == "rel", a.Name.Local == "type":
				default:
					t.Fatalf("unexpected attribute %s on %s", a.Name.Local, el.Name.Local)
				}
			}
			depth++
			stack = append(stack, el.Name.Local)
			text.Reset()
		case xml.CharData:
			text.Write(el)
		case xml.EndElement:
			depth--
			switch v := text.String(); el.Name.Local {
			case "updated":
				// Atom dates must be RFC 3339; the feeds write UTC seconds.
				if !utcRE.MatchString(v) {
					t.Fatalf("updated %q isn't an RFC 3339 UTC time", v)
				}
			case "id":
				if ids[v] {
					t.Fatalf("id %q used twice", v)
				}
				ids[v] = true
			}
			stack = stack[:len(stack)-1]
			text.Reset()
		case xml.ProcInst:
			if el.Target != "xml" {
				t.Fatalf("processing instruction %s", el.Target)
			}
		case xml.Directive:
			t.Fatalf("directive %s", el)
		}
	}
	return entries
}

func TestFeedFile(t *testing.T) {
	safe := regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*\.xml$`)
	seen := map[string]string{}
	for _, ref := range []string{"php:8.4-apache", "PHP:8.4-apache", "a/b:c", "a-b:c", "ghcr.io/acme/app:1.2", "..", "", strings.Repeat("x", 300) + ":1"} {
		f := FeedFile(ref)
		if !safe.MatchString(f) || len(f) > 100 {
			t.Errorf("FeedFile(%q) = %q", ref, f)
		}
		if other, dup := seen[f]; dup {
			t.Errorf("%q and %q share %s", ref, other, f)
		}
		seen[f] = ref
		if FeedFile(ref) != f {
			t.Errorf("FeedFile(%q) isn't stable", ref)
		}
	}
	if f := FeedFile("php:8.4-apache"); !strings.HasPrefix(f, "php-8.4-apache-") {
		t.Errorf("got %s", f)
	}
}

func feedIndex() *Index {
	return &Index{Generated: "2026-10-31T05:30:00Z", Entries: []Entry{
		{Ref: "php:8.4-apache", Platform: "linux/amd64"},
		{Ref: "php:8.4-apache", Platform: "linux/arm64"},
		{Ref: "wordpress:latest", Platform: "linux/amd64"},
	}}
}

func feedHistory() []Change {
	v := map[string]string{"CVE-2026-109618": "VULNERABLE", "CVE-2026-109619": "VULNERABLE"}
	f := map[string]string{"CVE-2026-109618": "FIXED", "CVE-2026-109619": "FIXED"}
	return []Change{
		{Time: "2026-10-30T22:00:00Z", Ref: "php:8.4-apache", Platform: "linux/amd64", ToDigest: "sha256:aa", ToAction: "ACTION_NEEDED", Verdicts: v},
		{Time: "2026-10-30T22:00:00Z", Ref: "wordpress:latest", Platform: "linux/amd64", ToDigest: "sha256:cc", ToAction: "OK", Verdicts: f},
		{Time: "2026-10-31T05:20:00Z", Ref: "php:8.4-apache", Platform: "linux/amd64", FromDigest: "sha256:aa", ToDigest: "sha256:bb", FromAction: "ACTION_NEEDED", ToAction: "OK", Verdicts: f},
		{Time: "not a time", Ref: "php:8.4-apache", Platform: "linux/amd64", ToAction: "OK"},
		{Time: "2026-10-29T00:00:00Z", Ref: "gone:1", Platform: "linux/amd64", ToAction: "OK"},
	}
}

func TestFeeds(t *testing.T) {
	feeds, err := Feeds(feedIndex(), feedHistory(), FeedOptions{SiteURL: testSite})
	if err != nil {
		t.Fatal(err)
	}
	php := FeedFile("php:8.4-apache")
	if len(feeds) != 3 || feeds[php] == nil || feeds[FeedFile("wordpress:latest")] == nil || feeds[AllFeed] == nil {
		t.Fatalf("got feeds %v", keys(feeds))
	}
	for name, b := range feeds {
		checkAtom(t, b)
		if !bytes.Contains(b, []byte(`href="`+testSite+"feeds/"+name+`"`)) {
			t.Errorf("%s has no self link", name)
		}
	}

	var f atomFeed
	if err := xml.Unmarshal(feeds[php], &f); err != nil {
		t.Fatal(err)
	}
	// Newest first; the unparseable time is dropped.
	if len(f.Entries) != 2 || f.Entries[0].Updated != "2026-10-31T05:20:00Z" || f.Updated != "2026-10-31T05:20:00Z" {
		t.Fatalf("entries %+v", f.Entries)
	}
	if got := f.Entries[0].Title; got != "php:8.4-apache (linux/amd64): no action needed, was action needed" {
		t.Errorf("title %q", got)
	}
	if got := f.Entries[1].Title; got != "php:8.4-apache (linux/amd64): first checked, action needed" {
		t.Errorf("title %q", got)
	}
	body := f.Entries[0].Content.Body
	for _, want := range []string{"Image digest: sha256:bb (was sha256:aa)", "CVE-2026-109618: FIXED", "Details: " + testSite + "?q=php%3A8.4-apache"} {
		if !strings.Contains(body, want) {
			t.Errorf("content lacks %q:\n%s", want, body)
		}
	}
	if f.Entries[0].ID == f.Entries[1].ID || !strings.HasPrefix(f.ID, "tag:example.github.io,2026:whichphp:feed:") {
		t.Errorf("ids %q %q %q", f.ID, f.Entries[0].ID, f.Entries[1].ID)
	}

	// A tag with no history still gets a valid, empty feed dated by the index.
	empty, _ := Feeds(&Index{Generated: "2026-10-31T05:30:00Z", Entries: []Entry{{Ref: "new:1"}}}, nil, FeedOptions{SiteURL: testSite})
	if n := checkAtom(t, empty[FeedFile("new:1")]); n != 0 || !bytes.Contains(empty[FeedFile("new:1")], []byte("<updated>2026-10-31T05:30:00Z</updated>")) {
		t.Errorf("empty feed:\n%s", empty[FeedFile("new:1")])
	}

	// all.xml has every change with a valid time, including tags no longer tracked.
	if n := checkAtom(t, feeds[AllFeed]); n != 4 {
		t.Errorf("all.xml has %d entries, want 4", n)
	}
	// Limits apply.
	limited, _ := Feeds(feedIndex(), feedHistory(), FeedOptions{SiteURL: testSite, MaxEntries: 1, MaxAllEntries: 2})
	if checkAtom(t, limited[php]) != 1 || checkAtom(t, limited[AllFeed]) != 2 {
		t.Error("limits not applied")
	}
}

func TestFeedsEscaping(t *testing.T) {
	ref := "evil<script>alert(1)</script>]]>&amp;\x00\x1b[31m\xff:1"
	idx := &Index{Generated: "2026-10-31T05:30:00Z", Entries: []Entry{{Ref: ref, Platform: "linux/amd64"}}}
	hist := []Change{{Time: "2026-10-31T05:20:00Z", Ref: ref, Platform: "<b>p</b>", ToDigest: "sha256:\"><x", ToAction: "<img src=x>",
		Verdicts: map[string]string{"CVE-1</content><entry>": "a\u2028b"}}}
	feeds, err := Feeds(idx, hist, FeedOptions{SiteURL: testSite})
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range feeds {
		if checkAtom(t, b) != 1 {
			t.Errorf("want one entry:\n%s", b)
		}
		if bytes.Contains(b, []byte("<script")) || bytes.Contains(b, []byte("<img")) {
			t.Errorf("markup leaked:\n%s", b)
		}
	}
}

func TestFeedsRejectsBadSiteURL(t *testing.T) {
	for _, u := range []string{"", "http://example.com/", "https://example.com", "javascript:alert(1)/", "https:///x/",
		"https://example.com/?x=1/", "https://example.com/#x/", "https://u:p@example.com/", "https://example.com/?", "https://example.com/#"} {
		if _, err := Feeds(feedIndex(), nil, FeedOptions{SiteURL: u}); err == nil {
			t.Errorf("site URL %q accepted", u)
		}
	}
}

func TestLoadHistory(t *testing.T) {
	dir := t.TempDir()
	if h, bad, err := LoadHistory(filepath.Join(dir, "missing.jsonl")); err != nil || h != nil || bad != 0 {
		t.Fatalf("missing file: %v %v %v", h, bad, err)
	}
	p := filepath.Join(dir, "history.jsonl")
	data := `{"time":"2026-10-31T05:20:00Z","ref":"php:8.4","platform":"linux/amd64","toAction":"OK"}
not json
{"time":"2026-10-31T05:21:00Z"}

{"time":"2026-10-31T05:22:00Z","ref":"php:8.3","platform":"linux/arm64","toAction":"ACTION_NEEDED"}
`
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	h, bad, err := LoadHistory(p)
	if err != nil || len(h) != 2 || bad != 2 || h[1].Ref != "php:8.3" {
		t.Fatalf("got %+v, %d bad, %v", h, bad, err)
	}
}

func TestSaveFeedsReplacesOldFeeds(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "feeds")
	if err := SaveFeeds(dir, map[string][]byte{"old.xml": []byte("x"), "keep.xml": []byte("1")}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SaveFeeds(dir, map[string][]byte{"keep.xml": []byte("2")}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "old.xml")); !os.IsNotExist(err) {
		t.Error("stale feed kept")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "keep.xml")); string(b) != "2" {
		t.Errorf("keep.xml = %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Error("a non-feed file was removed")
	}
	for _, bad := range []string{"../x.xml", "a/b.xml", "x.html"} {
		if err := SaveFeeds(dir, map[string][]byte{bad: nil}); err == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// FuzzFeeds: references, platforms, digests and verdicts reach the feeds from images
// and from the index. Whatever they contain, every feed must stay a well-formed Atom
// document with only Atom elements, text content and links to the site.
func FuzzFeeds(f *testing.F) {
	f.Add("php:8.4-apache", "linux/amd64", "sha256:aa", "OK", "CVE-2026-109618", "FIXED", "2026-10-31T05:20:00Z")
	f.Add("a<b>]]>&", "<p>", "\x00", "<x>", "</content>", "\xff\xfe", "2026-10-31T05:20:00+03:00")
	f.Fuzz(func(t *testing.T, ref, platform, digest, action, cve, verdict, stamp string) {
		if ref == "" {
			ref = "x"
		}
		idx := &Index{Generated: stamp, Entries: []Entry{{Ref: ref, Platform: platform}}}
		hist := []Change{{Time: stamp, Ref: ref, Platform: platform, FromDigest: digest, ToDigest: digest + "1", FromAction: verdict, ToAction: action, Verdicts: map[string]string{cve: verdict}}}
		feeds, err := Feeds(idx, hist, FeedOptions{SiteURL: testSite})
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range feeds {
			checkAtom(t, b)
		}
	})
}

func TestFeedFileStartsWithLetterOrDigit(t *testing.T) {
	site := regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}\.xml$`) // the index page's rule
	for _, ref := range []string{"_x/y:1", "__", "._-", "-a", strings.Repeat("_", 200) + "a", "a" + strings.Repeat("_", 79) + "b"} {
		if f := FeedFile(ref); !site.MatchString(f) {
			t.Errorf("FeedFile(%q) = %q", ref, f)
		}
	}
}

// Times may come with offsets or fractions: the feeds sort them by instant and write
// UTC, and repeated history lines give one entry.
func TestFeedsTimes(t *testing.T) {
	idx := &Index{Generated: "2026-10-31T06:00:00Z", Entries: []Entry{{Ref: "php:8.4-apache", Platform: "linux/amd64"}}}
	c := func(stamp, digest string) Change {
		return Change{Time: stamp, Ref: "php:8.4-apache", Platform: "linux/amd64", ToDigest: digest, ToAction: "OK"}
	}
	hist := []Change{
		c("2026-10-31T08:00:00+03:00", "sha256:a"), // 05:00Z
		c("2026-10-31T05:30:00.5Z", "sha256:b"),
		c("2026-10-31T05:30:00.5Z", "sha256:b"), // repeated line
		c("2026-10-31T04:59:00Z", "sha256:c"),
		c("not a time", "sha256:d"),
	}
	feeds, err := Feeds(idx, hist, FeedOptions{SiteURL: testSite})
	if err != nil {
		t.Fatal(err)
	}
	b := feeds[FeedFile("php:8.4-apache")]
	if n := checkAtom(t, b); n != 3 {
		t.Fatalf("%d entries, want 3:\n%s", n, b)
	}
	var f struct {
		Updated string `xml:"updated"`
		Entries []struct {
			Updated string `xml:"updated"`
		} `xml:"entry"`
	}
	if err := xml.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	got := []string{f.Updated}
	for _, e := range f.Entries {
		got = append(got, e.Updated)
	}
	if want := "2026-10-31T05:30:00Z 2026-10-31T05:30:00Z 2026-10-31T05:00:00Z 2026-10-31T04:59:00Z"; strings.Join(got, " ") != want {
		t.Errorf("times %v, want %s", got, want)
	}
}

// A line too long to read is skipped like any bad line, and the rest still loads.
func TestLoadHistoryLongLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.jsonl")
	good := `{"time":"2026-10-31T05:20:00Z","ref":"php:8"}`
	long := `{"time":"2026-10-31T05:20:00Z","ref":"` + strings.Repeat("x", maxHistoryLine) + `"}`
	if err := os.WriteFile(path, []byte(good+"\n"+long+"\n"+good+"\n"+good), 0o644); err != nil {
		t.Fatal(err)
	}
	h, bad, err := LoadHistory(path)
	if err != nil || len(h) != 3 || bad != 1 {
		t.Errorf("got %d changes, %d bad, %v", len(h), bad, err)
	}
}

// SaveFeeds removes only the .xml files in its own directory, whatever characters
// the path has.
func TestSaveFeedsOddDirectoryNames(t *testing.T) {
	root := t.TempDir()
	other := filepath.Join(root, "ab")
	dir := filepath.Join(root, "a*")
	for _, d := range []string{other, dir, filepath.Join(root, "[x")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	keep := filepath.Join(other, "keep.xml")
	if err := os.WriteFile(keep, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SaveFeeds(dir, map[string][]byte{"a.xml": []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("a feed in another directory was removed: %v", err)
	}
	if err := SaveFeeds(filepath.Join(root, "[x"), map[string][]byte{"a.xml": []byte("x")}); err != nil {
		t.Errorf("directory with [: %v", err)
	}
	// Only regular .xml files are old feeds.
	if err := os.Mkdir(filepath.Join(dir, "sub.xml"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SaveFeeds(dir, map[string][]byte{"b.xml": []byte("x")}); err != nil {
		t.Fatalf("with a directory named .xml: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "a.xml")); err == nil {
		t.Error("old feed a.xml left behind")
	}
}

func TestXMLText(t *testing.T) {
	for in, want := range map[string]string{"a\x01b": "a b", "a\nb\tc": "a\nb\tc", "\xff": "\ufffd", "a\u0085b": "a b", "a\ufffeb": "a b"} {
		if got := xmlText(in); got != want {
			t.Errorf("xmlText(%q) = %q, want %q", in, got, want)
		}
	}
}
