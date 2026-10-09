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

// minioTimestampPattern is a MinIO release named by its UTC timestamp, the
// way NVD and BDU both write MinIO's bounds ("2025-10-15t17-29-55z", in
// either case). It folds into the same dotted "2025.10.15.17.29.55" that
// version.Clean makes of the probed "RELEASE.2025-10-15T17-29-55Z". The T
// and Z keep a plain date bound ("2015-04-01") out of it.
var minioTimestampPattern = regexp.MustCompile(`^(?i)(\d{4})-(\d{2})-(\d{2})t(\d{2})-(\d{2})-(\d{2})z$`)

// boundFolds rewrites one CVE product's version strings — the bounds in
// both sources, and the probed version in Subject — into the dotted shape
// cleanVersionParts reads, for a product numbered in a shape no other
// product shares. rangeTexts turns the parsed parts back into that
// product's own notation for the report.
var (
	boundFolds = map[string]func(string) string{"synology-dsm": foldSynologyBuilds}
	rangeTexts = map[string]func([]int) string{"synology-dsm": synologyBuildText}
)

// synologyBuildPattern is a DSM release as Synology, NVD and BDU write it:
// version, build, and optionally the Update ("7.2.1-69057-6"; once in NVD
// "6.2.4-25556.4"). The release before the build may lack its patch
// number ("7.2-64570").
var synologyBuildPattern = regexp.MustCompile(`\b(\d+)\.(\d+)(?:\.(\d+))?-(\d{4,5})(?:[-.](\d+))?\b`)

// foldSynologyBuilds rewrites every DSM release in s as
// major.minor.patch.build.update, the missing patch and Update as 0, so
// "7.2-64570-4" is 7.2.0.64570.4 and orders after a bare "7.2" bound and
// before 7.2.1.
func foldSynologyBuilds(s string) string {
	return synologyBuildPattern.ReplaceAllStringFunc(s, func(m string) string {
		g := synologyBuildPattern.FindStringSubmatch(m)
		for _, i := range []int{3, 5} {
			if g[i] == "" {
				g[i] = "0"
			}
		}
		return strings.Join([]string{g[1], g[2], g[3], g[4], g[5]}, ".")
	})
}

// synologyBuildText writes folded DSM parts back as "7.2.1-69057-6".
// DSM's releases have no x.y.0, so a 0 patch is the one the fold added.
func synologyBuildText(parts []int) string {
	if len(parts) < 4 {
		return joinParts(parts)
	}
	out := joinParts(parts[:2])
	if parts[2] != 0 {
		out += "." + strconv.Itoa(parts[2])
	}
	out += "-" + strconv.Itoa(parts[3])
	if len(parts) > 4 && parts[4] != 0 {
		out += "-" + strconv.Itoa(parts[4])
	}
	return out
}

// foldBound applies product's entry in boundFolds to s, if it has one.
func foldBound(product, s string) string {
	if fold := boundFolds[product]; fold != nil {
		return fold(s)
	}
	return s
}

// rangeText is r.String() in product's own notation.
func rangeText(product string, r versionRange) string {
	if text := rangeTexts[product]; text != nil {
		return r.format(text)
	}
	return r.String()
}

// cleanVersionParts returns version.Parts(s) only when s, trimmed, is
// wholly a dotted-number version with nothing else attached.
func cleanVersionParts(s string) ([]int, bool) {
	s = strings.TrimSpace(s)
	if m := minioTimestampPattern.FindStringSubmatch(s); m != nil {
		s = strings.Join(m[1:], ".")
	}
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
// (anything from Lo on is vulnerable, i.e. no fix is known yet). Neither
// parser produces both nil: an entry with no version information at all
// is rejected at parse time (see parseNVDRange), so matches never has to
// decide what "no constraint" means.
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
func (r versionRange) String() string { return r.format(joinParts) }

func (r versionRange) format(joinParts func([]int) string) string {
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
