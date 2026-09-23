// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"strings"

	"github.com/EpicMorg/enodia/internal/version"
)

// Subject translates one observation (its probe product id, raw Version,
// and Extra) into what the CVE tables are keyed on: a CVE product, the
// version to compare, and the edition when the probe reports one. ok is
// false when there's nothing meaningful to look up at all.
//
// Two translations exist today, each for a real case found against live
// data rather than anticipated:
//   - ssh: one probe covers every SSH server, but OpenSSH and Dropbear are
//     unrelated codebases with unrelated CVEs. The probe's Version is the
//     whole RFC 4253 software string ("OpenSSH_9.6p1", "dropbear_2022.83"),
//     so its prefix says which one this is; anything else (a vendor's own
//     SSH stack) has no CVE product mapped, and gets no lookup rather than
//     borrowing OpenSSH's findings.
//   - gitlab: CE and EE share one version numbering but not one CVE list —
//     five of GitLab 19.2.2's nine real NVD findings are EE-only. The
//     probe already reports /api/v4/version's own "enterprise" boolean in
//     Extra; a version string's own "-ee"/"-ce" suffix is the fallback for
//     an inventory that predates that field.
//
// Every other product is its own CVE product, with no edition.
func Subject(product, rawVersion string, extra map[string]string) (cveProduct, cveVersion, edition string, ok bool) {
	switch product {
	case "ssh":
		software, _, _ := strings.Cut(rawVersion, " ")
		name, ver, found := strings.Cut(software, "_")
		if !found {
			return "", "", "", false
		}
		switch strings.ToLower(name) {
		case "openssh":
			return "openssh", ver, "", true
		case "dropbear":
			return "dropbear", ver, "", true
		default:
			return "", "", "", false
		}
	case "gitlab":
		return product, version.Clean(rawVersion), gitlabEdition(rawVersion, extra), true
	default:
		return product, version.Clean(rawVersion), "", true
	}
}

// gitlabEdition maps GitLab's own edition signal onto NVD's CPE sw_edition
// vocabulary ("community"/"enterprise", confirmed live as the only two
// values GitLab's CVE configurations use besides the unrestricted "*"/"-").
func gitlabEdition(rawVersion string, extra map[string]string) string {
	switch extra["enterprise"] {
	case "true":
		return "enterprise"
	case "false":
		return "community"
	}
	switch version.Edition(rawVersion) {
	case "ee", "enterprise":
		return "enterprise"
	case "ce", "community":
		return "community"
	}
	return ""
}
