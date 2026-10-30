// Package syftjson reads the parts of a Syft JSON document that whichphp needs.
package syftjson

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Document is a Syft JSON SBOM, reduced to the fields whichphp uses.
type Document struct {
	Artifacts  []Artifact `json:"artifacts"`
	Files      []File     `json:"files"`
	Source     Source     `json:"source"`
	Distro     Distro     `json:"distro"`
	Descriptor struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"descriptor"`
}

// Artifact is a package Syft found.
type Artifact struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Version   string     `json:"version"`
	Type      string     `json:"type"`
	FoundBy   string     `json:"foundBy"`
	PURL      string     `json:"purl"`
	CPEs      CPEList    `json:"cpes"`
	Locations []Location `json:"locations"`
}

// Location is where Syft found evidence for an artifact or file.
type Location struct {
	Path       string `json:"path"`
	AccessPath string `json:"accessPath"`
	LayerID    string `json:"layerID"`
}

// File is a file entry; Contents is base64-encoded when the file-content cataloger ran.
type File struct {
	ID       string   `json:"id"`
	Location Location `json:"location"`
	Contents string   `json:"contents"`
}

// Distro is the Linux distribution Syft detected.
type Distro struct {
	ID        string `json:"id"`
	VersionID string `json:"versionID"`
	Name      string `json:"name"`
}

// Source describes what was scanned.
type Source struct {
	Type     string          `json:"type"`
	Name     string          `json:"name"`
	Version  string          `json:"version"`
	Metadata json.RawMessage `json:"metadata"`
}

// ImageMetadata is Syft's metadata for an image source.
type ImageMetadata struct {
	UserInput      string   `json:"userInput"`
	ImageID        string   `json:"imageID"`
	ManifestDigest string   `json:"manifestDigest"`
	Tags           []string `json:"tags"`
	RepoDigests    []string `json:"repoDigests"`
	Architecture   string   `json:"architecture"`
	OS             string   `json:"os"`
	// Config is the raw image config, base64-encoded by Syft.
	Config []byte `json:"config"`
}

// ImageConfig is the part of an OCI image config whichphp reads.
type ImageConfig struct {
	Created      string `json:"created"`
	Architecture string `json:"architecture"`
	Config       struct {
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
	} `json:"config"`
}

// CPEList accepts both the old (strings) and current (objects) Syft CPE encodings.
type CPEList []string

// UnmarshalJSON implements json.Unmarshaler.
func (c *CPEList) UnmarshalJSON(b []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		var s string
		if err := json.Unmarshal(r, &s); err == nil {
			out = append(out, s)
			continue
		}
		var obj struct {
			CPE string `json:"cpe"`
		}
		if err := json.Unmarshal(r, &obj); err == nil && obj.CPE != "" {
			out = append(out, obj.CPE)
		}
	}
	*c = out
	return nil
}

// Load reads a Syft JSON document from disk.
func Load(path string) (*Document, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse decodes a Syft JSON document.
func Parse(b []byte) (*Document, error) {
	var d Document
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("not a Syft JSON document: %w", err)
	}
	if d.Descriptor.Name != "" && d.Descriptor.Name != "syft" {
		return nil, fmt.Errorf("SBOM was produced by %q; whichphp needs Syft JSON", d.Descriptor.Name)
	}
	return &d, nil
}

// Image returns the image metadata and decoded config when the source is an image.
func (d *Document) Image() (*ImageMetadata, *ImageConfig) {
	if d.Source.Type != "image" || len(d.Source.Metadata) == 0 {
		return nil, nil
	}
	var md ImageMetadata
	if err := json.Unmarshal(d.Source.Metadata, &md); err != nil {
		return nil, nil
	}
	var cfg ImageConfig
	if len(md.Config) > 0 && json.Unmarshal(md.Config, &cfg) == nil {
		return &md, &cfg
	}
	return &md, nil
}

// Created parses the image creation time, if known.
func (c *ImageConfig) CreatedTime() (time.Time, bool) {
	if c == nil || c.Created == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, c.Created)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// FileContents returns the decoded contents of every file the content cataloger
// captured, keyed by path.
func (d *Document) FileContents() map[string]string {
	out := map[string]string{}
	for _, f := range d.Files {
		if f.Contents == "" {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(f.Contents)
		if err != nil {
			continue
		}
		out[f.Location.Path] = string(data)
	}
	return out
}

// HasCPE reports whether any of the artifact's CPEs contains the given fragment.
func (a Artifact) HasCPE(fragment string) bool {
	for _, c := range a.CPEs {
		if strings.Contains(c, fragment) {
			return true
		}
	}
	return false
}

// Paths returns the artifact's evidence paths.
func (a Artifact) Paths() []string {
	var out []string
	for _, l := range a.Locations {
		if l.Path != "" {
			out = append(out, l.Path)
		}
	}
	return out
}
