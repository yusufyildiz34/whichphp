// Package advisory holds the facts whichphp's verdicts rest on: the CVEs, the affected
// ranges, the first fixed releases and which distro releases still get security updates.
//
// Sources (checked October 30, 2026):
//   - PHP release announcements for 8.5.12, 8.4.27, 8.3.36 and 8.2.35 (October 21, 2026).
//   - NVD CPE ranges, analyzed October 28–29, 2026: CVE-2026-109618 from 7.3.0,
//     CVE-2026-109619 from 5.4.0.
//   - CVSS v4.0 9.2 for both CVEs, from PHP's announcement (php.net, October 21, 2026).
//   - CVE-2026-115560 has no fix yet; the mitigation is session.upload_progress.enabled=0.
package advisory

import "time"

// CVEs are the PHP2Shell vulnerabilities whichphp gives verdicts for.
var CVEs = []string{"CVE-2026-109618", "CVE-2026-109619"}

// Severity is the CVSS v4.0 base score that PHP, the CVE Numbering Authority, gave
// each CVE in its October 21, 2026 announcement. NVD's CVSS 3.1 scores are 9.8 for
// CVE-2026-109618 and 8.1 for CVE-2026-109619.
var Severity = map[string]string{
	"CVE-2026-109618": "9.2",
	"CVE-2026-109619": "9.2",
}

// MitigationCVE is the related, still-unfixed CVE whose mitigation whichphp checks.
const MitigationCVE = "CVE-2026-115560"

// MitigationSetting is the php.ini directive that mitigates MitigationCVE when off.
const MitigationSetting = "session.upload_progress.enabled"

// RangeStart is the first affected version for each CVE, per NVD.
var RangeStart = map[string][3]int{
	"CVE-2026-109618": {7, 3, 0},
	"CVE-2026-109619": {5, 4, 0},
}

// Fixed is the first upstream release with the fix, per supported branch.
var Fixed = map[[2]int][3]int{
	{8, 2}: {8, 2, 35},
	{8, 3}: {8, 3, 36},
	{8, 4}: {8, 4, 27},
	{8, 5}: {8, 5, 12},
}

// PreReleaseBranch is the branch in pre-release when the fix shipped, and FixedRC is
// its first release candidate that carries the fix.
var (
	PreReleaseBranch = [2]int{8, 6}
	FixedRC          = 4
)

// FixReleased is when the fixed releases were published.
var FixReleased = time.Date(2026, 10, 21, 13, 30, 0, 0, time.UTC)

// DistroFeeds are distros whose security data Grype's database carries.
var DistroFeeds = map[string]bool{
	"debian": true, "ubuntu": true, "alpine": true, "rhel": true, "centos": true,
	"almalinux": true, "rocky": true, "amzn": true, "ol": true, "wolfi": true,
	"chainguard": true, "sles": true, "opensuse-leap": true, "photon": true,
	"mariner": true, "azurelinux": true,
}

// supportedReleases lists distro releases that still receive security updates as of
// October 30, 2026. Releases not listed for a known distro are treated as end-of-life.
var supportedReleases = map[string]map[string]bool{
	"debian":    {"12": true, "13": true},
	"ubuntu":    {"22.04": true, "24.04": true, "26.04": true},
	"alpine":    {"3.21": true, "3.22": true, "3.23": true, "3.24": true},
	"rhel":      {"8": true, "9": true, "10": true},
	"almalinux": {"8": true, "9": true, "10": true},
	"rocky":     {"8": true, "9": true, "10": true},
	"ol":        {"8": true, "9": true, "10": true},
	"amzn":      {"2023": true},
}

var rolling = map[string]bool{"wolfi": true, "chainguard": true, "arch": true, "opensuse-tumbleweed": true}

// DistroSupport is whether a distro release still gets security updates.
type DistroSupport int

const (
	SupportUnknown DistroSupport = iota
	Supported
	EndOfLife
)

// Support reports whether the given distro release still receives security updates.
func Support(id, versionID string) DistroSupport {
	if rolling[id] {
		return Supported
	}
	rel, ok := supportedReleases[id]
	if !ok || versionID == "" {
		return SupportUnknown
	}
	if rel[NormalizeRelease(id, versionID)] {
		return Supported
	}
	return EndOfLife
}

// NormalizeRelease reduces a distro version to the granularity its support policy uses:
// "3.22.1" → "3.22" for Alpine, "12.8" → "12" for Debian and the RHEL family.
func NormalizeRelease(id, versionID string) string {
	switch id {
	case "alpine":
		return firstN(versionID, 2)
	case "debian", "rhel", "almalinux", "rocky", "ol", "centos":
		return firstN(versionID, 1)
	}
	return versionID
}

func firstN(v string, n int) string {
	parts := 0
	for i, r := range v {
		if r == '.' {
			parts++
			if parts == n {
				return v[:i]
			}
		}
	}
	return v
}
