// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cve correlates a probed product version against a locally
// supplied vulnerability database. The only source implemented today is
// FSTEC's БДУ (Банк данных угроз безопасности информации,
// bdu.fstec.ru) — a Russian government threat/vulnerability bank that,
// unlike OSV.dev (see docs/DECISIONS.md D18), keys its affected-software
// ranges to the product's own version numbering rather than a Linux
// distro's packaged version, and does carry entries for proprietary
// products (Atlassian's among them) OSV.dev has none for at all.
//
// enodia never fetches this itself: the file is large (the full export is
// several hundred MB of XML) and BDU has no documented, stable API to poll
// politely. The operator downloads it themselves, on whatever schedule
// they like, and points `cve.bdu.path` at it (see docs/DECISIONS.md D30).
package cve

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/EpicMorg/enodia/internal/version"
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

// cleanVersionPattern is deliberately stricter than version.Parts: Parts
// extracts the first numeric-and-dots run it finds *anywhere* in a string,
// which is right for "2025.03.1 (build 42)" but wrong here — confirmed
// live that it would silently accept "24.2R2-EVO" as "24.2" and
// "2015-04-01" (a literal date used as a range bound in real BDU data) as
// plain "2015". A bound only counts if the *entire* trimmed string is
// nothing but digits and dots.
var cleanVersionPattern = regexp.MustCompile(`^\d+(?:\.\d+)*$`)

// cleanVersionParts returns version.Parts(s) only when s, trimmed, is
// wholly a dotted-number version with nothing else attached.
func cleanVersionParts(s string) ([]int, bool) {
	s = strings.TrimSpace(s)
	if !cleanVersionPattern.MatchString(s) {
		return nil, false
	}
	parts := version.Parts(s)
	if len(parts) == 0 {
		return nil, false
	}
	return parts, true
}

// bduRange is one <soft>'s parsed <version> field: the vulnerable range is
// [Lo, Hi) if HiInclusive is false, [Lo, Hi] if true. A nil Lo means
// "no stated lower bound" (BDU's bare "до X" shape) — every version up to
// Hi is treated as vulnerable, not just versions from some unstated floor.
type bduRange struct {
	Lo          []int
	Hi          []int
	HiInclusive bool
}

// parseBDUVersion turns one <soft><version> string into a bduRange, or
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
func parseBDUVersion(raw string) (bduRange, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return bduRange{}, false
	}

	// Tried before bduBoundedRangePattern: "до X" alone has nothing before
	// "до" at all, which bduBoundedRangePattern's non-empty lower-bound
	// group cannot represent.
	if m := bduOpenLowerPattern.FindStringSubmatch(raw); m != nil {
		hiParts, ok := cleanVersionParts(m[1])
		if !ok {
			return bduRange{}, false
		}
		return bduRange{Hi: hiParts, HiInclusive: strings.TrimSpace(m[2]) != ""}, true
	}

	if m := bduBoundedRangePattern.FindStringSubmatch(raw); m != nil {
		loParts, ok := cleanVersionParts(m[1])
		if !ok {
			return bduRange{}, false
		}
		hiParts, ok := cleanVersionParts(m[2])
		if !ok {
			return bduRange{}, false
		}
		return bduRange{Lo: loParts, Hi: hiParts, HiInclusive: strings.TrimSpace(m[3]) != ""}, true
	}

	// No "от"/"до" at all: a bare version, e.g. "3.2.2.21". Treated as an
	// exact single-point match — [X, X] inclusive — not "at least X" or
	// "up to X", since the source text asserts neither of those, only that
	// this specific build was the one found vulnerable.
	parts, ok := cleanVersionParts(raw)
	if !ok {
		return bduRange{}, false
	}
	return bduRange{Lo: parts, Hi: parts, HiInclusive: true}, true
}

// matches reports whether probed (already a clean version.Parts-able
// string) falls inside r.
func (r bduRange) matches(probed []int) bool {
	if len(probed) == 0 {
		return false
	}
	if r.Lo != nil && comparePartsSlices(probed, r.Lo) < 0 {
		return false
	}
	cmp := comparePartsSlices(probed, r.Hi)
	if r.HiInclusive {
		return cmp <= 0
	}
	return cmp < 0
}

// comparePartsSlices compares two already-parsed version.Parts results the
// same way version.Compare compares two raw strings — shorter slices are
// treated as zero-padded, so 10.3 == 10.3.0.
func comparePartsSlices(a, b []int) int {
	n := max(len(a), len(b))
	for i := range n {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
	}
	return 0
}

// String renders r as a human-readable range, for diagnostics only —
// never re-parsed, purely for a person to read in a --view or export
// field.
func (r bduRange) String() string {
	hi := joinParts(r.Hi)
	if r.Lo == nil {
		if r.HiInclusive {
			return "up to and including " + hi
		}
		return "before " + hi
	}
	lo := joinParts(r.Lo)
	if r.HiInclusive {
		return lo + " through " + hi
	}
	return lo + " up to (not including) " + hi
}

func joinParts(parts []int) string {
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = strconv.Itoa(p)
	}
	return strings.Join(out, ".")
}
