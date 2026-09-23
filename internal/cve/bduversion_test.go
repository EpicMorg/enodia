// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"testing"

	"github.com/EpicMorg/enodia/internal/version"
)

func TestParseBDUVersion(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		ok   bool
	}{
		{"clean from-to", "от 11.0.0 до 11.0.7", true},
		{"clean from-to inclusive", "от 4.5 до 4.9.192 включительно", true},
		{"bare upper bound", "до 23.3.36", true},
		{"bare upper bound short", "до 43", true},
		{"bare version", "3.2.2.21", true},
		{"missing от, malformed", "24.2 до 24.2R2-EVO", false},
		{"cisco-style, not a version", "9.3(7)", false},
		{"date as bound", "от 6.0 до 2015-04-01", false},
		{"placeholder dot", ".", false},
		{"placeholder dash", "-", false},
		{"vendor garbage", "B FRN 15.002", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := parseBDUVersion(tc.raw)
			if ok != tc.ok {
				t.Errorf("parseBDUVersion(%q) ok = %v, want %v", tc.raw, ok, tc.ok)
			}
		})
	}
}

// These two ranges are real BDU data for two independently, publicly
// documented CVEs — not synthetic examples — used specifically to pin
// down the inclusive/exclusive meaning of "включительно" against known
// ground truth rather than assumption (see bduversion.go's doc comment).
func TestParseBDUVersionInclusiveSemantics(t *testing.T) {
	// CVE-2023-22515: Atlassian's own advisory names 8.3.3 as the fixed
	// version on this branch, so it must NOT be flagged as still vulnerable.
	confluence, ok := parseBDUVersion("от 8.0.0 до 8.3.3")
	if !ok {
		t.Fatal("expected the Confluence range to parse")
	}
	if confluence.matches(version.Parts("8.3.3")) {
		t.Error("8.3.3 is Atlassian's own published fix version and must not match")
	}
	if !confluence.matches(version.Parts("8.3.2")) {
		t.Error("8.3.2 is before the fix and must match")
	}
	if !confluence.matches(version.Parts("8.0.0")) {
		t.Error("8.0.0 is the stated lower bound and must match")
	}

	// Log4Shell, CVE-2021-44228: 2.17.0 is the first release safe from the
	// whole disclosure, so it must NOT be flagged as still vulnerable
	// either — same "bare 'до X' excludes X" rule.
	log4j, ok := parseBDUVersion("до 2.17.0")
	if !ok {
		t.Fatal("expected the Log4j range to parse")
	}
	if log4j.matches(version.Parts("2.17.0")) {
		t.Error("2.17.0 is the first safe release and must not match")
	}
	if !log4j.matches(version.Parts("2.14.1")) {
		t.Error("2.14.1 predates the fix and must match")
	}
	if !log4j.matches(version.Parts("0.1.0")) {
		t.Error("a bare upper bound has no stated floor; anything below it must match")
	}

	// A real kernel-style range using "включительно": the upper bound is
	// itself still a vulnerable build (the fix is the version after it),
	// the opposite of the two cases above.
	kernel, ok := parseBDUVersion("от 4.5 до 4.9.192 включительно")
	if !ok {
		t.Fatal("expected the kernel range to parse")
	}
	if !kernel.matches(version.Parts("4.9.192")) {
		t.Error("4.9.192 is explicitly included and must match")
	}
	if kernel.matches(version.Parts("4.9.193")) {
		t.Error("one past the inclusive upper bound must not match")
	}
}

func TestParseBDUVersionBareVersionIsExactPoint(t *testing.T) {
	r, ok := parseBDUVersion("3.2.2.21")
	if !ok {
		t.Fatal("expected a bare version to parse")
	}
	if !r.matches(version.Parts("3.2.2.21")) {
		t.Error("the exact listed version must match")
	}
	if r.matches(version.Parts("3.2.2.22")) {
		t.Error("a bare version must not match anything but itself")
	}
	if r.matches(version.Parts("3.2.2.20")) {
		t.Error("a bare version must not match anything but itself")
	}
}
