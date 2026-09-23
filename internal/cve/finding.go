// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import "github.com/EpicMorg/enodia/internal/version"

// Finding is one product/CVE match extracted from a vulnerability source
// (BDU or NVD), kept only for products that source's own product map
// names. Every field is the source's own data carried through as-is (D7:
// facts, not a verdict) — Severity is the source's own published rating,
// not something this project computed.
type Finding struct {
	Source      string   // "bdu" or "nvd"
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
}

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
	var out []Finding
	for _, f := range idx.byProduct[product] {
		if edition != "" && f.Edition != "" && f.Edition != edition {
			continue
		}
		if f.Matches(probed) {
			out = append(out, f)
		}
	}
	return out
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
	return a
}
