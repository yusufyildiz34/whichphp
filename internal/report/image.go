package report

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/yusufyildiz34/whichphp/internal/registry"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

// repoURL is where whichphp lives; SARIF and OpenVEX output link to it.
const repoURL = "https://github.com/yusufyildiz34/whichphp"

// Source schemes Syft accepts. The first group names an image in a registry or a
// container runtime; the second names files or directories on this machine.
var (
	imageSchemes = []string{"registry:", "docker:", "podman:", "containerd:"}
	localSchemes = []string{"docker-archive:", "oci-archive:", "oci-dir:", "dir:", "file:", "singularity:"}
)

// Docker reference grammar, and digests as the OCI spec writes them.
var (
	repoRE   = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)
	tagRE    = regexp.MustCompile(`^\w[\w.-]{0,127}$`)
	digestRE = regexp.MustCompile(`^(sha256:[a-f0-9]{64}|sha512:[a-f0-9]{128})$`)
)

// imageRef parses s as an image reference (with or without a registry: style scheme)
// and reports whether it is one. Paths and archives are not.
func imageRef(s string) (registry.Ref, bool) {
	for _, p := range localSchemes {
		if strings.HasPrefix(s, p) {
			return registry.Ref{}, false
		}
	}
	for _, p := range imageSchemes {
		s = strings.TrimPrefix(s, p)
	}
	if s == "" || strings.ContainsAny(s, `\ `) || strings.HasPrefix(s, "/") || strings.HasPrefix(s, ".") || strings.HasPrefix(s, "~") {
		return registry.Ref{}, false
	}
	ref, err := registry.ParseRef(s)
	if err != nil || !repoRE.MatchString(ref.Repository) || (ref.Tag != "" && !tagRE.MatchString(ref.Tag)) ||
		(ref.Digest != "" && !digestRE.MatchString(ref.Digest)) {
		return registry.Ref{}, false
	}
	ref.Registry = strings.ToLower(ref.Registry)
	return ref, true
}

// imageLabel names the image for people: its first tag, the reference it was given
// as, or for a local archive or directory only its base name, so that reports never
// carry a path from the machine that produced them.
func imageLabel(r verdict.Report) string {
	for _, t := range r.Image.Tags {
		if _, ok := imageRef(t); ok {
			return t
		}
	}
	in := r.Image.Input
	if _, ok := imageRef(in); ok {
		for _, p := range imageSchemes {
			in = strings.TrimPrefix(in, p)
		}
		return in
	}
	for _, p := range localSchemes {
		in = strings.TrimPrefix(in, p)
	}
	in = strings.TrimRight(strings.ReplaceAll(in, `\`, "/"), "/")
	if base := path.Base(in); base != "" && base != "." && base != "/" {
		return base
	}
	return "image"
}

// imageRepo names the image without its tag or digest (registry/repository), so
// rebuilds and per-commit tags of the same image are recognized as one. Archives and
// directories keep their label.
func imageRepo(r verdict.Report) string {
	label := imageLabel(r)
	if ref, ok := imageRef(label); ok {
		return ref.Registry + "/" + ref.Repository
	}
	return label
}

// imagePURL is the package URL (pkg:oci) of a scanned image, or "" when the report
// doesn't identify one: the source isn't an image, or there is no name or digest.
//
// Only a repo digest, or an explicit registry: input, says which registry the image
// came from, so only then does the purl carry a repository_url. A locally built or
// loaded image gets a purl without one rather than a claim about Docker Hub.
func imagePURL(r verdict.Report) string {
	if r.Image.SourceType != "image" {
		return ""
	}
	var origin registry.Ref
	digest := ""
	for _, rd := range r.Image.RepoDigests {
		if ref, ok := imageRef(rd); ok && ref.Digest != "" {
			origin, digest = ref, ref.Digest
			break
		}
	}
	if origin.Repository == "" && strings.HasPrefix(r.Image.Input, "registry:") {
		if ref, ok := imageRef(r.Image.Input); ok {
			origin, digest = ref, ref.Digest
		}
	}
	if digest == "" {
		digest = strings.ToLower(r.Image.ManifestDigest)
	}
	if !digestRE.MatchString(digest) {
		return ""
	}

	repo, tag := origin.Repository, origin.Tag
	for _, t := range r.Image.Tags {
		ref, ok := imageRef(t)
		if !ok || (repo != "" && (ref.Registry != origin.Registry || ref.Repository != repo)) {
			continue
		}
		if repo == "" {
			repo = ref.Repository
		}
		if tag == "" {
			tag = ref.Tag
		}
		break
	}
	if repo == "" && namesImage(r.Image.Input) {
		if ref, ok := imageRef(r.Image.Input); ok {
			repo = ref.Repository
			if tag == "" {
				tag = ref.Tag
			}
		}
	}
	if repo == "" {
		return ""
	}

	name := repo[strings.LastIndex(repo, "/")+1:]
	out := "pkg:oci/" + purlEscape(name) + "@" + purlEscape(digest)
	var q []string
	if r.Image.Architecture != "" {
		q = append(q, "arch="+purlEscape(r.Image.Architecture))
	}
	if origin.Repository != "" {
		host := origin.Registry
		if host == "registry-1.docker.io" {
			host = "index.docker.io"
		}
		q = append(q, "repository_url="+purlEscape(host+"/"+origin.Repository))
	}
	if tag != "" {
		q = append(q, "tag="+purlEscape(tag))
	}
	if len(q) == 0 {
		return out
	}
	return out + "?" + strings.Join(q, "&")
}

// namesImage reports whether an input clearly names an image rather than a file: it
// has an image scheme, or carries a tag or digest and doesn't end like an archive.
// "build/app.tar" is a valid reference by grammar, but Syft reads it as a file.
func namesImage(in string) bool {
	for _, p := range imageSchemes {
		if strings.HasPrefix(in, p) {
			return true
		}
	}
	low := strings.ToLower(in)
	for _, ext := range []string{".tar", ".tgz", ".tar.gz", ".zip", ".sif"} {
		if strings.HasSuffix(low, ext) {
			return false
		}
	}
	return strings.ContainsAny(in, ":@")
}

// phpPURL is Syft's purl for a PHP package, or a generic one built from its name.
func phpPURL(p verdict.PHP) string {
	if p.PURL != "" {
		return p.PURL
	}
	out := "pkg:generic/" + purlEscape(strings.ToLower(p.Name))
	if p.Version != "" {
		out += "@" + purlEscape(p.Version)
	}
	return out
}

// purlEscape percent-encodes everything except the unreserved characters, as
// packageurl-go does, so "/" in a repository_url becomes %2F.
func purlEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
