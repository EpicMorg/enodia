// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cve correlates a probed product version against a locally
// supplied vulnerability database. Two sources are implemented:
//
//   - FSTEC's БДУ (Банк данных угроз безопасности информации,
//     bdu.fstec.ru) — a Russian government threat/vulnerability bank that,
//     unlike OSV.dev (see docs/DECISIONS.md D18), keys its affected-software
//     ranges to the product's own version numbering rather than a Linux
//     distro's packaged version, and does carry entries for proprietary
//     products (Atlassian's among them) OSV.dev has none for at all. See
//     docs/DECISIONS.md D30.
//   - NIST's NVD (nvd.nist.gov), via its yearly downloadable JSON exports
//     (not the live API — see docs/DECISIONS.md D31 for why). NVD's own
//     CPE-match version ranges (versionStart/EndIncluding/Excluding) are
//     the same product-own-numbering shape BDU's ranges are, cross-checked
//     against the very same real CVEs D30/D31 already verify.
//
// enodia never fetches either of these itself: both are large, and neither
// has a documented, stable API meant to be polled on every collection
// cycle. The operator downloads them on whatever schedule they like and
// points `cve.bdu.path`/`cve.nvd.path` at the result.
package cve

import (
	"regexp"
	"strings"
)

// bduBoundedRangePattern matches a range with a stated lower bound: "от X
// до Y[ включительно]" — but also, confirmed live against the real corpus,
// a bare "X до Y" with the "от" dropped entirely (53 instances in the full
// export, e.g. "0.4.0 до 0.4.39") — so "от" is optional here, not the
// whole lower-bound clause.
var bduBoundedRangePattern = regexp.MustCompile(`(?i)^\s*(?:от\s+)?(.+?)\s+до\s+(.+?)(\s+включительно)?\s*$`)

// bduOpenLowerPattern matches BDU's other shape, with no lower bound at
// all: "до X[ включительно]". Kept separate from
// bduBoundedRangePattern rather than folded in with an optional group,
// since "nothing at all before до" and "some text before до" need
// different capture-group arities to stay unambiguous.
var bduOpenLowerPattern = regexp.MustCompile(`(?i)^\s*до\s+(.+?)(\s+включительно)?\s*$`)

// parseBDUVersion turns one <soft><version> string into a versionRange, or
// reports ok=false for anything that isn't a clean, comparable version —
// confirmed live that this field is genuinely mixed: clean dotted
// versions and ranges sit next to vendor build tags ("10.1.0.126
// (C461E7R3P1)"), Cisco-style strings ("9.3(7)"), bare punctuation ("-",
// "."), and even a literal date used as a range bound. Silently matching
// against any of those would be a wrong verdict, not a missing one — D7's
// facts-not-guesses rule applies here exactly as it does to a probe.
//
// The inclusive/exclusive distinction on the upper bound was verified
// against two well-known, independently documented CVEs, not assumed:
// Atlassian's CVE-2023-22515 ("от 8.0.0 до 8.3.3", no "включительно") —
// 8.3.3 is Atlassian's own published fix version, i.e. already safe, so
// bare "до X" must exclude X — and Log4Shell, CVE-2021-44228 ("до
// 2.17.0", no "включительно") — 2.17.0 is likewise the first safe
// release on that branch. Every "включительно" instance sampled instead
// describes a last-known-vulnerable build (e.g. a Linux kernel point
// release), which only makes sense as an inclusive upper bound.
func parseBDUVersion(raw string) (versionRange, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return versionRange{}, false
	}

	// Tried before bduBoundedRangePattern: "до X" alone has nothing before
	// "до" at all, which bduBoundedRangePattern's non-empty lower-bound
	// group cannot represent.
	if m := bduOpenLowerPattern.FindStringSubmatch(raw); m != nil {
		hiParts, ok := cleanVersionParts(m[1])
		if !ok {
			return versionRange{}, false
		}
		return versionRange{Hi: hiParts, HiInclusive: strings.TrimSpace(m[2]) != ""}, true
	}

	if m := bduBoundedRangePattern.FindStringSubmatch(raw); m != nil {
		loParts, ok := cleanVersionParts(m[1])
		if !ok {
			return versionRange{}, false
		}
		hiParts, ok := cleanVersionParts(m[2])
		if !ok {
			return versionRange{}, false
		}
		// BDU's "от X" has no exclusive-lower-bound counterpart anywhere in
		// the real corpus — only the upper bound's включительно varies.
		return versionRange{Lo: loParts, LoInclusive: true, Hi: hiParts, HiInclusive: strings.TrimSpace(m[3]) != ""}, true
	}

	// No "от"/"до" at all: a bare version, e.g. "3.2.2.21". Treated as an
	// exact single-point match — [X, X] inclusive — not "at least X" or
	// "up to X", since the source text asserts neither of those, only that
	// this specific build was the one found vulnerable.
	parts, ok := cleanVersionParts(raw)
	if !ok {
		return versionRange{}, false
	}
	return versionRange{Lo: parts, LoInclusive: true, Hi: parts, HiInclusive: true}, true
}
