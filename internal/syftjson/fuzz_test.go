package syftjson

import "testing"

// FuzzParse: an SBOM can be handed to whichphp with --sbom, so it is untrusted input.
// Parsing it and reading its image metadata and file contents must never panic.
func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"descriptor":{"name":"syft"},"source":{"type":"image","metadata":{"userInput":"php:8.4","config":"e30="}},"artifacts":[{"name":"php","cpes":["x",{"cpe":"y"}]}],"files":[{"location":{"path":"/a"},"contents":"Zm9v"}]}`))
	f.Add([]byte(`{"source":{"type":"image","metadata":"x"}}`))
	f.Add([]byte(`{"artifacts":[{"cpes":{}}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := Parse(b)
		if err != nil {
			return
		}
		md, cfg := d.Image()
		_ = md
		cfg.CreatedTime()
		_ = d.FileContents()
		for _, a := range d.Artifacts {
			_ = a.Paths()
		}
	})
}
