package report

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/yusufyildiz34/whichphp/internal/advisory"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

// Clock and document IDs, replaceable in tests.
var (
	now   = time.Now
	newID = func() (string, error) {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		b[6] = b[6]&0x0f | 0x40
		b[8] = b[8]&0x3f | 0x80
		return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
	}
)

// VEXOptions configures OpenVEX output.
type VEXOptions struct {
	// Author is the person or organization that issues the document. VEX consumers
	// decide whether to apply statements by who wrote them.
	Author string
}

type vexDoc struct {
	Context    string         `json:"@context"`
	ID         string         `json:"@id"`
	Author     string         `json:"author"`
	Role       string         `json:"role"`
	Timestamp  string         `json:"timestamp"`
	Version    int            `json:"version"`
	Tooling    string         `json:"tooling"`
	Statements []vexStatement `json:"statements"`
}

type vexStatement struct {
	Vulnerability   vexVuln      `json:"vulnerability"`
	Products        []vexProduct `json:"products"`
	Status          string       `json:"status"`
	Justification   string       `json:"justification,omitempty"`
	ActionStatement string       `json:"action_statement,omitempty"`
	StatusNotes     string       `json:"status_notes,omitempty"`
}

type vexVuln struct {
	Name string `json:"name"`
}

type vexProduct struct {
	ID            string            `json:"@id"`
	Identifiers   map[string]string `json:"identifiers,omitempty"`
	Subcomponents []vexComponent    `json:"subcomponents,omitempty"`
}

type vexComponent struct {
	ID          string            `json:"@id"`
	Identifiers map[string]string `json:"identifiers,omitempty"`
}

// OpenVEX writes the report as an OpenVEX v0.2.0 document: one statement per CVE for
// each PHP in the image, scoped to that PHP as a subcomponent of the image.
//
// VEX consumers use "fixed" and "not_affected" to suppress scanner findings, so only
// positive evidence produces them: a fixed version, a confirmed distro backport, or a
// version older than the first affected release. Vulnerable PHP is "affected"; every
// uncertain case, including an image where whichphp found no PHP, is
// "under_investigation".
//
// The product is the image's pkg:oci purl. Directories, and archives without a tag or
// digest, can't be named that way, so OpenVEX returns an error for them.
func OpenVEX(w io.Writer, r verdict.Report, opt VEXOptions) error {
	product := imagePURL(r)
	if product == "" {
		return errors.New("OpenVEX output needs an image with a name and a manifest digest; " +
			"this source has none (a directory, or an archive without a tag)")
	}
	id, err := newID()
	if err != nil {
		return fmt.Errorf("making a document ID: %w", err)
	}
	author := strings.TrimSpace(opt.Author)
	if author == "" {
		author = "whichphp automated scan (" + repoURL + ")"
	}
	doc := vexDoc{
		Context:   "https://openvex.dev/ns/v0.2.0",
		ID:        id,
		Author:    author,
		Role:      "automated scanner",
		Timestamp: now().UTC().Format(time.RFC3339),
		Version:   1,
		Tooling:   strings.TrimSpace("whichphp " + r.Version),
	}
	for _, cve := range advisory.CVEs {
		if len(r.PHP) == 0 {
			doc.Statements = append(doc.Statements, vexStatement{
				Vulnerability: vexVuln{Name: cve},
				Products:      []vexProduct{{ID: product, Identifiers: map[string]string{"purl": product}}},
				Status:        "under_investigation",
				StatusNotes:   "whichphp found no PHP in this image. That is not proof the image is unaffected: a PHP build whichphp doesn't recognize would be missed.",
			})
			continue
		}
		for _, p := range r.PHP {
			res := p.CVEs[cve]
			sub := phpPURL(p)
			st := vexStatement{
				Vulnerability: vexVuln{Name: cve},
				Products: []vexProduct{{
					ID: product, Identifiers: map[string]string{"purl": product},
					Subcomponents: []vexComponent{{ID: sub, Identifiers: map[string]string{"purl": sub}}},
				}},
				StatusNotes: fmt.Sprintf("%s %s (%s, %s): %s: %s", p.Name, p.Version, p.Source, p.SAPI, res.Verdict, res.Why),
			}
			switch {
			case res.Verdict == verdict.Fixed, res.Verdict == verdict.FixedByDistroBackport && !res.Unconfirmed:
				st.Status = "fixed"
			case res.Verdict == verdict.NotAffected:
				st.Status, st.Justification = "not_affected", "vulnerable_code_not_present"
			case res.Verdict.IsVulnerable():
				st.Status = "affected"
				st.ActionStatement = "Rebuild or replace the image with PHP " + fixedReleases() +
					", or a distro package that carries the backport. PHP 8.1 and older get no upstream fix."
			default:
				st.Status = "under_investigation"
			}
			doc.Statements = append(doc.Statements, st)
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}
