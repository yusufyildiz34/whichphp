package index

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// AllFeed is the file name of the feed with the latest changes across the index.
const AllFeed = "all.xml"

// FeedOptions control the Atom feeds.
type FeedOptions struct {
	// SiteURL is where the index page is published, ending in "/". Feeds are served
	// from its feeds/ directory.
	SiteURL string
	// MaxEntries bounds each tag's feed; MaxAllEntries bounds all.xml.
	MaxEntries, MaxAllEntries int
}

var slugRE = regexp.MustCompile(`[^a-z0-9._]+`)

// FeedFile returns the file name of a tag's Atom feed, for example
// "php-8.4-apache-1a2b3c4d.xml": the reference made file-name safe, plus a short hash
// of the exact reference so that two references can't share a file.
func FeedFile(ref string) string {
	// The site accepts feed names that start with a letter or digit.
	slug := strings.Trim(slugRE.ReplaceAllString(strings.ToLower(ref), "-"), "-._")
	if len(slug) > 80 {
		slug = strings.Trim(slug[:80], "-._")
	}
	sum := sha256.Sum256([]byte(ref))
	if slug == "" {
		return hex.EncodeToString(sum[:4]) + ".xml"
	}
	return slug + "-" + hex.EncodeToString(sum[:4]) + ".xml"
}

// LoadHistory reads a history.jsonl file. A missing file is an empty history. Lines
// that don't parse are skipped and counted, so one bad line can't stop the feeds.
func LoadHistory(path string) ([]Change, int, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	var out []Change
	bad := 0
	r := bufio.NewReader(f)
	for {
		line, tooLong, err := readLine(r, maxHistoryLine)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, 0, err
		}
		if line = bytes.TrimSpace(line); tooLong {
			bad++
		} else if len(line) > 0 {
			var c Change
			if json.Unmarshal(line, &c) != nil || c.Ref == "" {
				bad++
			} else {
				out = append(out, c)
			}
		}
		if err != nil {
			return out, bad, nil
		}
	}
}

// maxHistoryLine bounds one history line; longer lines are skipped as bad.
const maxHistoryLine = 4 << 20

// readLine reads up to the next newline. A line longer than max is read to its end
// but not returned, and tooLong is set.
func readLine(r *bufio.Reader, max int) (line []byte, tooLong bool, err error) {
	for {
		chunk, err := r.ReadSlice('\n')
		if !tooLong {
			if len(line)+len(chunk) > max {
				tooLong, line = true, nil
			} else {
				line = append(line, chunk...)
			}
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return line, tooLong, err
		}
	}
}

// Feeds builds an Atom feed for every tag in the index, named by FeedFile, plus
// AllFeed with the latest changes across all tags. Entries come from the history,
// newest first.
func Feeds(idx *Index, history []Change, opt FeedOptions) (map[string][]byte, error) {
	site, err := url.Parse(opt.SiteURL)
	if err != nil || site.Scheme != "https" || site.Host == "" || !strings.HasSuffix(site.Path, "/") ||
		site.User != nil || site.RawQuery != "" || site.ForceQuery || site.Fragment != "" || strings.Contains(opt.SiteURL, "#") {
		return nil, fmt.Errorf("site URL must be https, end in \"/\" and have no user, query or fragment, not %q", opt.SiteURL)
	}
	if opt.MaxEntries <= 0 {
		opt.MaxEntries = 50
	}
	if opt.MaxAllEntries <= 0 {
		opt.MaxAllEntries = 100
	}

	// Keep changes with a usable time, written as UTC RFC 3339 so the feeds are
	// valid whatever the history holds, and drop repeated lines.
	type timed struct {
		Change
		at time.Time
	}
	var list []timed
	seen := map[string]bool{}
	for _, c := range history {
		t, err := time.Parse(time.RFC3339, c.Time)
		if err != nil {
			continue
		}
		c.Time = t.UTC().Format(time.RFC3339)
		key := entryKey(c)
		if seen[key] {
			continue
		}
		seen[key] = true
		list = append(list, timed{c, t})
	}
	// Newest first; ties in a stable order.
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if !a.at.Equal(b.at) {
			return a.at.After(b.at)
		}
		if a.Ref != b.Ref {
			return a.Ref < b.Ref
		}
		return a.Platform < b.Platform
	})
	changes := make([]Change, len(list))
	for i, c := range list {
		changes[i] = c.Change
	}

	byRef := map[string][]Change{}
	for _, c := range changes {
		byRef[c.Ref] = append(byRef[c.Ref], c)
	}
	refs := map[string]bool{}
	for _, e := range idx.Entries {
		refs[e.Ref] = true
	}

	out := map[string][]byte{}
	for ref := range refs {
		file := FeedFile(ref)
		if _, dup := out[file]; dup {
			return nil, fmt.Errorf("two references share the feed file %s", file)
		}
		list := byRef[ref]
		if len(list) > opt.MaxEntries {
			list = list[:opt.MaxEntries]
		}
		b, err := writeFeed(site, file, atomFeedHead{
			title:    "whichphp: " + ref,
			subtitle: "Changes to the PHP2Shell status (CVE-2026-109618, CVE-2026-109619) of " + ref + ", per platform.",
			page:     pageURL(site, ref),
		}, list, idx.Generated)
		if err != nil {
			return nil, err
		}
		out[file] = b
	}
	all := changes
	if len(all) > opt.MaxAllEntries {
		all = all[:opt.MaxAllEntries]
	}
	b, err := writeFeed(site, AllFeed, atomFeedHead{
		title:    "whichphp: all index changes",
		subtitle: "The latest changes to the PHP2Shell status of the images in the whichphp index.",
		page:     site.String(),
	}, all, idx.Generated)
	if err != nil {
		return nil, err
	}
	out[AllFeed] = b
	return out, nil
}

// SaveFeeds writes the feeds into dir. It first removes the .xml files a previous run
// left there, so a tag dropped from the index loses its feed.
func SaveFeeds(dir string, feeds map[string][]byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	old, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range old {
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".xml") {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				return err
			}
		}
	}
	for name, b := range feeds {
		if strings.ContainsAny(name, `/\`) || !strings.HasSuffix(name, ".xml") {
			return fmt.Errorf("bad feed file name %q", name)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

type atomFeedHead struct{ title, subtitle, page string }

type atomFeed struct {
	XMLName   xml.Name    `xml:"http://www.w3.org/2005/Atom feed"`
	Title     string      `xml:"title"`
	Subtitle  string      `xml:"subtitle"`
	ID        string      `xml:"id"`
	Updated   string      `xml:"updated"`
	Links     []atomLink  `xml:"link"`
	Author    atomPerson  `xml:"author"`
	Generator string      `xml:"generator"`
	Entries   []atomEntry `xml:"entry"`
}

type atomLink struct {
	Rel  string `xml:"rel,attr"`
	Type string `xml:"type,attr,omitempty"`
	Href string `xml:"href,attr"`
}

type atomPerson struct {
	Name string `xml:"name"`
	URI  string `xml:"uri"`
}

type atomEntry struct {
	Title   string   `xml:"title"`
	ID      string   `xml:"id"`
	Updated string   `xml:"updated"`
	Link    atomLink `xml:"link"`
	Content atomText `xml:"content"`
}

type atomText struct {
	Type string `xml:"type,attr"`
	Body string `xml:",chardata"`
}

func writeFeed(site *url.URL, file string, head atomFeedHead, list []Change, generated string) ([]byte, error) {
	src, updated := generated, "1970-01-01T00:00:00Z"
	if len(list) > 0 {
		src = list[0].Time
	}
	if t, err := time.Parse(time.RFC3339, src); err == nil {
		updated = t.UTC().Format(time.RFC3339)
	}
	self := site.JoinPath("feeds", file).String()
	f := atomFeed{
		Title:    xmlText(head.title),
		Subtitle: xmlText(head.subtitle),
		ID:       tagURI(site, "feed", file),
		Updated:  updated,
		Links: []atomLink{
			{Rel: "self", Type: "application/atom+xml", Href: self},
			{Rel: "alternate", Type: "text/html", Href: head.page},
		},
		Author:    atomPerson{Name: "whichphp", URI: "https://github.com/yusufyildiz34/whichphp"},
		Generator: "whichphp",
	}
	for _, c := range list {
		f.Entries = append(f.Entries, atomEntry{
			Title:   xmlText(entryTitle(c)),
			ID:      tagURI(site, "change", entryKey(c)),
			Updated: c.Time,
			Link:    atomLink{Rel: "alternate", Type: "text/html", Href: pageURL(site, c.Ref)},
			Content: atomText{Type: "text", Body: xmlText(entryText(c, pageURL(site, c.Ref)))},
		})
	}
	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

var actionLabels = map[string]string{
	"OK":            "no action needed",
	"ACTION_NEEDED": "action needed",
	"UNKNOWN":       "not proven fixed",
	"NO_PHP":        "no PHP found",
	noBuildAction:   "no build for this platform",
}

func actionLabel(a string) string {
	if l, ok := actionLabels[a]; ok {
		return l
	}
	if a == "" {
		return "not checked"
	}
	return "unrecognized status " + a
}

func entryTitle(c Change) string {
	to := actionLabel(c.ToAction)
	switch {
	case c.FromAction == "" && c.FromDigest == "":
		return fmt.Sprintf("%s (%s): first checked, %s", c.Ref, c.Platform, to)
	case c.FromAction != c.ToAction:
		return fmt.Sprintf("%s (%s): %s, was %s", c.Ref, c.Platform, to, actionLabel(c.FromAction))
	case c.FromDigest != c.ToDigest:
		return fmt.Sprintf("%s (%s): new image, still %s", c.Ref, c.Platform, to)
	default:
		return fmt.Sprintf("%s (%s): verdicts changed, %s", c.Ref, c.Platform, to)
	}
}

func entryText(c Change, page string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Status: %s", actionLabel(c.ToAction))
	if c.FromAction != "" && c.FromAction != c.ToAction {
		fmt.Fprintf(&b, " (was %s)", actionLabel(c.FromAction))
	}
	b.WriteString(".\n")
	if c.ToDigest != "" {
		fmt.Fprintf(&b, "Image digest: %s", c.ToDigest)
		if c.FromDigest != "" && c.FromDigest != c.ToDigest {
			fmt.Fprintf(&b, " (was %s)", c.FromDigest)
		}
		b.WriteString("\n")
	}
	cves := make([]string, 0, len(c.Verdicts))
	for k := range c.Verdicts {
		cves = append(cves, k)
	}
	sort.Strings(cves)
	for _, k := range cves {
		fmt.Fprintf(&b, "%s: %s\n", k, c.Verdicts[k])
	}
	fmt.Fprintf(&b, "Checked by the whichphp index at %s.\nDetails: %s\n", c.Time, page)
	return b.String()
}

// entryKey identifies a change, for its Atom id and to drop repeated history lines.
func entryKey(c Change) string {
	return c.Ref + "\x00" + c.Platform + "\x00" + c.Time + "\x00" + c.ToDigest
}

func pageURL(site *url.URL, ref string) string {
	u := *site
	u.RawQuery = url.Values{"q": {ref}}.Encode()
	return u.String()
}

// tagURI makes a stable RFC 4151 tag URI for an Atom id.
func tagURI(site *url.URL, kind, key string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + key))
	return fmt.Sprintf("tag:%s,2026:whichphp:%s:%s", site.Hostname(), kind, hex.EncodeToString(sum[:16]))
}

// xmlText drops what XML 1.0 can't carry and invalid UTF-8; control characters other
// than newline and tab become spaces. Text in the feeds comes from images and from
// the index, so it must never break the document.
func xmlText(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case unicode.IsControl(r), r == '￾', r == '￿', r >= 0xD800 && r <= 0xDFFF:
			return ' '
		}
		return r
	}, s)
}
