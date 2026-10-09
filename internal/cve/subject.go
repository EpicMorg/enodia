// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"regexp"
	"strings"

	"github.com/EpicMorg/enodia/internal/version"
)

// Subject translates one observation (its probe product id, raw Version,
// and Extra) into what the CVE tables are keyed on: a CVE product, the
// version to compare, and the edition when the probe reports one. ok is
// false when there's nothing meaningful to look up at all.
//
// The translations, each for a real case found against live data rather
// than anticipated:
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
//   - vault, nextcloud, mongodb: the same CE/EE split shows up in both
//     NVD (sw_edition "enterprise") and BDU (separate "Vault Enterprise",
//     "Nextcloud Enterprise Server", "MongoDB Enterprise Server"
//     products); each probe reports its server's own edition in the same
//     Extra["enterprise"] key.
//   - splunk: NVD splits splunk:splunk by sw_edition into "enterprise"
//     and the long-retired "light"; the probe's Extra["productType"] is
//     splunkd's own name for which one it is ("enterprise", "lite").
//   - pfsense: NVD's netgate:pfsense mixes Community Edition (2.x) and
//     Plus (calendar-numbered, "< 22.05") ranges under sw_edition; the
//     probe reports CE only, so a Plus range never applies.
//   - wapt: the probe reports WAPT's own edition, already in NVD's
//     "community"/"enterprise" words.
//   - jenkins: weekly ("2.580") and LTS ("2.568.3") releases get the same
//     fixes under different numbers, and NVD and BDU write a range for
//     each; the version's own shape says which line it is (see
//     findingEdition).
//   - kafka: a Confluent Platform build ("7.6.1-ccs") is numbered on
//     Confluent's own scheme, which would read as far newer than every
//     Apache Kafka bound — and the Kafka release it carries is known only
//     to major.minor, not enough for a patch-level fix. No lookup.
//   - dell-idrac: NVD and BDU name each iDRAC generation as its own
//     product (idrac6_firmware … idrac10_firmware, "iDRAC9"), and iDRAC7/8
//     firmware 2.x and iDRAC10's 1.x overlap other generations' numbers.
//     The probe's Extra["model"] ("12G Modular") is the server generation,
//     which says the iDRAC one; without it only iDRAC9's 3.x and later are
//     unambiguous.
//   - synology-dsm: a release is version, build and Update ("7.2.1-69057
//     Update 6", bounds "7.2.1-69057-6"); the probe reports the Update in
//     Extra["update"], and both fold into one dotted version
//     (foldSynologyBuilds).
//
// Every other product is its own CVE product, with no edition — grafana
// included, whose CVE data splits by edition too but whose probed
// endpoint (/api/health) doesn't say which it is.
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
	case "vault", "nextcloud", "mongodb":
		return product, version.Clean(rawVersion), editionFromExtra(extra), true
	case "splunk":
		return product, version.Clean(rawVersion), splunkEditions[extra["productType"]], true
	case "pfsense":
		return product, version.Clean(rawVersion), "community", true
	case "wapt":
		e := extra["edition"]
		if e != "community" && e != "enterprise" {
			e = ""
		}
		return product, version.Clean(rawVersion), e, true
	case "jenkins":
		v := version.Clean(rawVersion)
		parts, _ := cleanVersionParts(v)
		return product, v, jenkinsChannel(parts), true
	case "kafka":
		if confluentBuild.MatchString(rawVersion) {
			return "", "", "", false
		}
		return product, version.Clean(rawVersion), "", true
	case "dell-idrac":
		v := version.Clean(rawVersion)
		cveProduct, ok := idracGeneration(v, extra["model"])
		return cveProduct, v, "", ok
	case "synology-dsm":
		v := version.Clean(rawVersion)
		if u := extra["update"]; u != "" {
			v += "-" + u
		}
		return product, foldSynologyBuilds(v), "", true
	default:
		return product, version.Clean(rawVersion), "", true
	}
}

// idracModelPattern is the PowerEdge generation at the start of iDRAC's
// Redfish Manager Model ("12G Modular", "14G Monolithic").
var idracModelPattern = regexp.MustCompile(`^(\d+)G\b`)

// idracGenerations maps a PowerEdge generation to its iDRAC's CVE product.
var idracGenerations = map[string]string{
	"11": "idrac6", "12": "idrac7", "13": "idrac8",
	"14": "idrac9", "15": "idrac9", "16": "idrac9", "17": "idrac10",
}

func idracGeneration(firmware, model string) (string, bool) {
	if m := idracModelPattern.FindStringSubmatch(strings.TrimSpace(model)); m != nil {
		p, ok := idracGenerations[m[1]]
		return p, ok
	}
	if parts, ok := cleanVersionParts(firmware); ok && parts[0] >= 3 {
		return "idrac9", true
	}
	return "", false
}

// splunkEditions maps splunkd's server/info product_type onto NVD's
// sw_edition words for splunk:splunk.
var splunkEditions = map[string]string{"enterprise": "enterprise", "lite": "light"}

// confluentBuild is a Confluent Platform Kafka version, the same shape the
// kafka probe recognises.
var confluentBuild = regexp.MustCompile(`^\d+\.\d+\.\d+-(?:ccs|ce)$`)

// editionFromExtra reads the Extra["enterprise"] fact the gitlab, vault,
// nextcloud and mongodb probes all report from their own API (see each
// probe), mapped onto NVD's CPE sw_edition vocabulary. Anything else —
// the key absent, as on an inventory collected before the probe learned
// to report it — is an unknown edition, which keeps every finding.
func editionFromExtra(extra map[string]string) string {
	switch extra["enterprise"] {
	case "true":
		return "enterprise"
	case "false":
		return "community"
	}
	return ""
}

// gitlabEdition maps GitLab's own edition signal onto NVD's CPE sw_edition
// vocabulary ("community"/"enterprise", confirmed live as the only two
// values GitLab's CVE configurations use besides the unrestricted "*"/"-").
func gitlabEdition(rawVersion string, extra map[string]string) string {
	if e := editionFromExtra(extra); e != "" {
		return e
	}
	switch version.Edition(rawVersion) {
	case "ee", "enterprise":
		return "enterprise"
	case "ce", "community":
		return "community"
	}
	return ""
}
