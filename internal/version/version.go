// SPDX-License-Identifier: AGPL-3.0-or-later

// Package version normalises and compares the version strings that vendors
// actually emit, which are not semver and never will be.
package version

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	rePrefix = regexp.MustCompile(`^\s*[vV]?(?:ersion\s*)?`)
	reTrail  = regexp.MustCompile(`(?i)[-+_](?:ee|ce|se|oss|enterprise|community|standard|final|ga|release|lts)\b.*$`)
	reCore   = regexp.MustCompile(`\d+(?:\.\d+)*`)
)

// Clean strips the decoration vendors hang off a version:
// "v10.3.2" -> "10.3.2", "17.8.1-ee" -> "17.8.1".
func Clean(raw string) string {
	s := rePrefix.ReplaceAllString(strings.TrimSpace(raw), "")
	s = reTrail.ReplaceAllString(s, "")
	if f := strings.Fields(s); len(f) > 0 {
		s = f[0]
	}
	return strings.TrimSpace(s)
}

// Core extracts the numeric spine:
// "2025.03.1 (build 42)" -> "2025.03.1".
func Core(raw string) string { return reCore.FindString(raw) }

// Edition reports the suffix a vendor uses to mark a distribution, if any.
func Edition(raw string) string {
	l := strings.ToLower(raw)
	for _, e := range []string{"ee", "ce", "enterprise", "community", "oss"} {
		if strings.Contains(l, "-"+e) || strings.HasSuffix(l, "."+e) {
			return e
		}
	}
	return ""
}

// Parts splits the numeric spine into integers. Leading zeros survive as
// values, so TeamCity's "2025.03" becomes {2025, 3} and still orders correctly.
func Parts(raw string) []int {
	core := Core(Clean(raw))
	if core == "" {
		return nil
	}
	segs := strings.Split(core, ".")
	out := make([]int, 0, len(segs))
	for _, s := range segs {
		n, err := strconv.Atoi(s)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

// Compare returns -1, 0 or 1, and ok=false when either side is unusable.
// Shorter versions compare as if padded with zeros: 10.3 == 10.3.0.
func Compare(a, b string) (int, bool) {
	pa, pb := Parts(a), Parts(b)
	if len(pa) == 0 || len(pb) == 0 {
		return 0, false
	}
	n := max(len(pa), len(pb))
	for i := range n {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		switch {
		case x < y:
			return -1, true
		case x > y:
			return 1, true
		}
	}
	return 0, true
}

// InCycle reports whether a version belongs to a release branch.
//
// Comparison is component-wise on purpose: a string prefix test would place
// 10.30.1 inside branch 10.3, which is wrong and would misreport lifecycle.
func InCycle(ver, cycle string) bool {
	pv, pc := Parts(ver), Parts(cycle)
	if len(pv) == 0 || len(pc) == 0 || len(pc) > len(pv) {
		return false
	}
	for i, c := range pc {
		if pv[i] != c {
			return false
		}
	}
	return true
}

// MatchCycle picks the most specific branch a version belongs to, so that
// 10.3.2 lands in "10.3" rather than "10" when both are published.
func MatchCycle(ver string, cycles []string) (string, bool) {
	best, bestLen := "", -1
	for _, c := range cycles {
		if !InCycle(ver, c) {
			continue
		}
		if n := len(Parts(c)); n > bestLen {
			best, bestLen = c, n
		}
	}
	return best, bestLen >= 0
}
