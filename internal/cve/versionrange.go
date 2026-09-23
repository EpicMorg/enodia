// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/EpicMorg/enodia/internal/version"
)

// cleanVersionPattern is deliberately stricter than version.Parts: Parts
// extracts the first numeric-and-dots run it finds *anywhere* in a string,
// which is right for "2025.03.1 (build 42)" but wrong here — confirmed
// live (against BDU's real corpus) that it would silently accept
// "24.2R2-EVO" as "24.2" and "2015-04-01" (a literal date used as a range
// bound in real data) as plain "2015". A bound only counts if the *entire*
// trimmed string is nothing but digits and dots.
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

// versionRange is one source's parsed vulnerable-version range, shared by
// every cve source this package knows about (BDU's free-text "от X до Y"
// and NVD's four separate versionStart/EndIncluding/Excluding fields both
// reduce to this same shape). A nil Lo means no stated lower bound
// (anything up to Hi is vulnerable); a nil Hi means no stated upper bound
// (anything from Lo on is vulnerable, i.e. no fix is known yet) — both nil
// means the source asserted no version constraint at all, which for NVD
// legitimately happens (a CPE match with no version fields at all, no
// known fixed version) and is treated as "every version matches", the same
// bias toward a false positive over a silent miss D30 already accepts for
// BDU's own overlapping-branch limitation.
type versionRange struct {
	Lo          []int
	LoInclusive bool // meaningless when Lo == nil
	Hi          []int
	HiInclusive bool // meaningless when Hi == nil
}

// matches reports whether probed (an already cleanVersionParts-parsed
// version) falls inside r.
func (r versionRange) matches(probed []int) bool {
	if len(probed) == 0 {
		return false
	}
	if r.Lo != nil {
		cmp := comparePartsSlices(probed, r.Lo)
		if r.LoInclusive {
			if cmp < 0 {
				return false
			}
		} else if cmp <= 0 {
			return false
		}
	}
	if r.Hi != nil {
		cmp := comparePartsSlices(probed, r.Hi)
		if r.HiInclusive {
			if cmp > 0 {
				return false
			}
		} else if cmp >= 0 {
			return false
		}
	}
	return true
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

// String renders r as a human-readable range, for diagnostics only — never
// re-parsed, purely for a person to read in a --view or export field.
func (r versionRange) String() string {
	switch {
	case r.Lo == nil && r.Hi == nil:
		return "any version"
	case r.Hi == nil:
		op := "from "
		if !r.LoInclusive {
			op = "after "
		}
		return op + joinParts(r.Lo)
	case r.Lo == nil:
		if r.HiInclusive {
			return "up to and including " + joinParts(r.Hi)
		}
		return "before " + joinParts(r.Hi)
	default:
		lo, hi := joinParts(r.Lo), joinParts(r.Hi)
		if r.LoInclusive && r.HiInclusive {
			return lo + " through " + hi
		}
		loOp, hiOp := ">=", "<"
		if !r.LoInclusive {
			loOp = ">"
		}
		if r.HiInclusive {
			hiOp = "<="
		}
		return loOp + lo + ", " + hiOp + hi
	}
}

func joinParts(parts []int) string {
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = strconv.Itoa(p)
	}
	return strings.Join(out, ".")
}
