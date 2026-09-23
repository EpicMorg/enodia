// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

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

	rng versionRange
}

// Matches reports whether probed (a raw version string, as a probe
// reports it) falls inside this finding's range.
func (f Finding) Matches(probed string) bool {
	parts, ok := cleanVersionParts(probed)
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

// Lookup returns every finding for product whose range contains probed.
func (idx *Index) Lookup(product, probed string) []Finding {
	if idx == nil {
		return nil
	}
	var out []Finding
	for _, f := range idx.byProduct[product] {
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
