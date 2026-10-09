// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import "github.com/EpicMorg/enodia/internal/version"

// Finding is one product/CVE match extracted from a vulnerability source
// (BDU or NVD), kept only for products that source's own product map
// names. Every field is the source's own data carried through as-is (D7:
// facts, not a verdict) — Severity is the source's own published rating,
// not something this project computed.
type Finding struct {
	Source      string   // "bdu", "nvd", "mariadb", "atlassian", or a package-level source (see InstalledVersion)
	AdvisoryID  string   // the source's own advisory id: "BDU:2023-06364" for BDU; for NVD, the CVE id again — NVD has no separate advisory id of its own
	CVEIDs      []string // e.g. ["CVE-2023-22515"]; may be empty — not every BDU entry cites one
	Title       string
	Severity    string // the source's own free-text severity
	MatchedName string // the exact BDU <soft><name>, or NVD CPE criteria, this range matched
	RangeText   string // the original version-range text, kept for display
	FixStatus   string
	// Edition is the product edition this range is restricted to — NVD's
	// CPE sw_edition field, or for BDU the edition its separately listed
	// product names ("Vault Enterprise") imply — or empty when the source
	// didn't restrict it. See Index.Lookup for how it's
	// matched against an observation's own edition.
	Edition string `json:",omitempty"`
	// CVSS is Severity parsed into a structured rating, for sorting and a
	// short display; the zero value when the source gave none this package
	// could parse. Severity itself stays the source's own text.
	CVSS CVSS `json:",omitzero"`
	// InstalledVersion and FixedVersion are set only on package-level
	// findings (Source "debian", "oval" or "alpine", see
	// Index.LookupPackages): the
	// package version on the host, and the version that fixes every CVE in
	// CVEIDs. MatchedName is then the package. AdvisoryID/AdvisoryURL name
	// the advisory that carries FixedVersion (USN-, RHSA-, ALSA-, ELSA-,
	// RLSA-), or for Debian the package's tracker page; Advisories is every
	// advisory the package is missing.
	InstalledVersion string   `json:",omitempty"`
	FixedVersion     string   `json:",omitempty"`
	AdvisoryURL      string   `json:",omitempty"`
	Advisories       []string `json:",omitempty"`

	rng versionRange
}

// CVSS is one structured rating: the CVSS version it's scored in, its base
// score (0 when the source gave only a qualitative level), and its
// severity in CVSS's own words (CRITICAL, HIGH, MEDIUM, LOW, NONE).
type CVSS struct {
	Version  string  `json:",omitempty"`
	Score    float64 `json:",omitempty"`
	Severity string  `json:",omitempty"`
}

// Matches reports whether probed falls inside this finding's range. Only
// probed's numeric spine is compared (version.Core: "9.6p1" -> "9.6",
// "1.3.8b" -> "1.3.8"): bounds are held to the strict whole-string rule
// (cleanVersionParts) because a garbage bound would be a wrong verdict,
// but probed comes from enodia's own probe, and the real NVD bounds for
// exactly these suffixed products are plain dotted numbers (OpenSSH's are
// "9.6", "10.4", never "9.6p1") — rejecting probed outright would silently
// match nothing at all for them.
func (f Finding) Matches(probed string) bool {
	parts, ok := cleanVersionParts(version.Core(probed))
	if !ok {
		return false
	}
	return f.rng.matches(parts)
}

// Index is a parsed, filtered vulnerability export — only the products
// this package's product maps know about, nothing else. Confirmed live:
// BDU's full export alone carries 90000+ entries across every vendor
// FSTEC tracks, the overwhelming majority of which enodia has no probe
// for at all and would just be dead weight to keep in memory or on disk.
//
// One real limitation, found live rather than guessed, that applies to
// BDU findings specifically: a single BDU <vul> can list several <soft>
// ranges for the very same product name, one per maintenance branch, each
// with its own fix version as the upper bound — confirmed against
// CVE-2023-22515's real Confluence entry ("от 8.0.0 до 8.3.3" / "8.4.3" /
// "8.5.2", one per branch, every one sharing the same lower bound). BDU's
// own data doesn't say which branch a range belongs to beyond the numbers
// themselves, so a widest-range match can flag an exact branch-fix version
// (8.3.3 here) as still vulnerable purely because it's numerically inside
// a wider *sibling* branch's range. Deliberately not "fixed": between
// silently under-reporting (a real miss) and occasionally telling someone
// to double-check a version that's actually already safe on its own
// branch, this project takes the side that doesn't risk a missed
// vulnerability. NVD's equivalent CPE-match data for the very same CVE
// does not share this limitation — its three ranges each carry their own
// lower bound too (8.0.0–8.3.3, 8.4.0–8.4.3, 8.5.0–8.5.2), so an NVD-only
// Finding for this CVE would not misfire the same way — see
// docs/DECISIONS.md D31.
type Index struct {
	byProduct map[string][]Finding
	debian    debianTracker           // nil unless cve.debian.path is configured
	oval      map[string]*ovalRelease // by ovalReleaseKey; nil unless cve.oval.path is configured
	alpine    alpineSecdb             // nil unless cve.alpine.path is configured
	// vendorCVEs is, per product, every CVE a vendor's own data covers
	// (MariaDB's, cve.mariadb.path; Atlassian's, cve.atlassian.path). For
	// those CVEs the vendor's verdict replaces BDU's and NVD's — see Lookup.
	vendorCVEs map[string]map[string]bool
	// vendorCovers is, per product, which releases a vendor's data speaks
	// for, when that isn't all of them: Atlassian's, only the releases it
	// lists; PostgreSQL's, only the majors its table names. Its verdict
	// holds only there — any other release keeps BDU's and NVD's findings.
	vendorCovers map[string]func(parts []int) bool
}

// vendorSources are the Finding.Source values of vendors' own data.
var vendorSources = map[string]bool{mariadbSource: true, atlassianSource: true, postgresqlSource: true, nginxSource: true}

// Lookup returns every finding for product whose range contains probed
// and whose edition applies. edition is the observation's own edition
// (see Subject), or "" when the probe doesn't know it — in which case
// every finding is kept regardless of its Edition, the same "false
// positive over a silent miss" bias D30 already takes. A finding with no
// Edition applies to every edition. Confirmed live why this matters: of
// GitLab 19.2.2's nine real NVD findings, five are Enterprise-only.
func (idx *Index) Lookup(product, probed, edition string) []Finding {
	if idx == nil {
		return nil
	}
	vendor := idx.vendorCVEs[product]
	var out []Finding
	for _, f := range idx.byProduct[product] {
		if fe := findingEdition(product, f); edition != "" && fe != "" && fe != edition {
			continue
		}
		if f.Matches(probed) {
			out = append(out, f)
		}
	}
	if vendor == nil {
		return out
	}
	if covers := idx.vendorCovers[product]; covers != nil {
		parts, ok := cleanVersionParts(version.Core(probed))
		if !ok || !covers(parts) {
			return out
		}
	}
	// The vendor's own data knows which series each CVE was fixed in;
	// BDU's and NVD's ranges for the same CVE often don't (D50). A BDU/NVD
	// finding survives only when the vendor flags this version for one of
	// its CVEs too, or when none of its CVEs are in the vendor's data at
	// all (newer than the vendor's table, or BDU-only).
	flagged := map[string]bool{}
	for _, f := range out {
		if vendorSources[f.Source] {
			for _, id := range f.CVEIDs {
				flagged[id] = true
			}
		}
	}
	kept := out[:0]
	for _, f := range out {
		if !vendorSources[f.Source] && vendorOverrides(f.CVEIDs, vendor, flagged) {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// findingEdition is f's Edition, or for jenkins, when the source left it
// unset, the release line its bounds are written in (see jenkinsChannel):
// NVD marks Jenkins LTS ranges "lts" but leaves weekly ones unmarked, and
// BDU marks neither — so a weekly "before 2.580" would otherwise flag LTS
// 2.568.3, which has the same fixes.
func findingEdition(product string, f Finding) string {
	if f.Edition != "" || product != "jenkins" {
		return f.Edition
	}
	if f.rng.Hi != nil {
		return jenkinsChannel(f.rng.Hi)
	}
	return jenkinsChannel(f.rng.Lo)
}

// jenkinsChannel is the Jenkins release line a version belongs to: weekly
// releases are numbered "2.580", LTS releases "2.568.3".
func jenkinsChannel(parts []int) string {
	switch len(parts) {
	case 2:
		return "weekly"
	case 3:
		return "lts"
	}
	return ""
}

// vendorOverrides reports whether a BDU/NVD finding with these CVEs is
// contradicted by the vendor's data: every CVE is known to the vendor,
// and the vendor flags none of them for this version.
func vendorOverrides(ids []string, known, flagged map[string]bool) bool {
	if len(ids) == 0 {
		return false
	}
	for _, id := range ids {
		if !known[id] || flagged[id] {
			return false
		}
	}
	return true
}

// MergeIndex combines a and b into one Index, mutating and returning
// whichever of the two is non-nil (or a, with b's findings appended, when
// both are). Nil-safe in both arguments, since either source (BDU, NVD)
// may be unconfigured — used to combine every configured source's Index
// into the one cve.Index the rest of the pipeline sees.
func MergeIndex(a, b *Index) *Index {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	}
	for product, findings := range b.byProduct {
		a.byProduct[product] = append(a.byProduct[product], findings...)
	}
	if a.debian == nil {
		a.debian = b.debian
	}
	if a.oval == nil {
		a.oval = b.oval
	}
	if a.alpine == nil {
		a.alpine = b.alpine
	}
	for product, ids := range b.vendorCVEs {
		if a.vendorCVEs == nil {
			a.vendorCVEs = map[string]map[string]bool{}
		}
		a.vendorCVEs[product] = ids
	}
	for product, covers := range b.vendorCovers {
		if a.vendorCovers == nil {
			a.vendorCovers = map[string]func([]int) bool{}
		}
		a.vendorCovers[product] = covers
	}
	return a
}
