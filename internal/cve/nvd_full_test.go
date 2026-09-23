// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"path/filepath"
	"testing"
)

// testdata/nvd_full_products.json is real NVD data, not synthetic: every
// one of NVD's own yearly exports for 2002 through 2026 (the full,
// unfiltered downloads verified live against each year's own .meta
// sha256, ~222MB compressed in total) was streamed through the exact same
// vendor/product filter productCPENames uses, keeping the complete,
// untrimmed CVE record for every one that mentions a mapped CPE — 561
// records — then trimming each record to only the fields LoadNVD actually
// reads (English description only, baseSeverity, configurations), the
// same "real but reduced" treatment BDU's own sample.xml got. This is
// the fixture docs/DECISIONS.md D31's "verified live against two full
// real yearly exports" note refers to extending to every year, not just
// 2023+2024.
//
// Regenerating it means re-running the filter+trim steps in D31 against
// a fresh set of yearly downloads — there is no committed generator
// script for this (a one-off tool, not something this package runs
// again on its own), so treat this file as a point-in-time real snapshot
// to test against, not something to keep in sync with NVD's live data.
func TestLoadNVDFullProductsFixture(t *testing.T) {
	idx, err := LoadNVD(filepath.Join("testdata", "nvd_full_products.json"))
	if err != nil {
		t.Fatalf("LoadNVD: %v", err)
	}

	has := func(findings []Finding, id string) bool {
		for _, f := range findings {
			if f.AdvisoryID == id {
				return true
			}
		}
		return false
	}

	// The same real, independently checkable CVEs already verified
	// against the full 25-year dataset live: CVE-2023-22515 (the D18/D30
	// callback) and CVE-2024-21683 (a real Jira Server LTS range), each
	// checked at both its own real fix version (must not match) and a
	// version inside its real vulnerable range (must match).
	if got := idx.Lookup("confluence", "8.3.3"); has(got, "CVE-2023-22515") {
		t.Error("CVE-2023-22515 must not match confluence 8.3.3, Atlassian's own real fix version")
	}
	if got := idx.Lookup("confluence", "8.3.0"); !has(got, "CVE-2023-22515") {
		t.Error("CVE-2023-22515 must match confluence 8.3.0")
	}
	if got := idx.Lookup("jira", "9.4.10"); !has(got, "CVE-2024-21683") {
		t.Error("CVE-2024-21683 must match jira 9.4.10 (a real Server LTS range)")
	}
	if got := idx.Lookup("jira", "9.4.21"); has(got, "CVE-2024-21683") {
		t.Error("CVE-2024-21683 must not match jira 9.4.21, its own real fix version")
	}

	// Coarse coverage sanity: every mapped product has real matches
	// somewhere in 25 years of data — a regression that silently
	// stopped matching one product entirely (e.g. a broken CPE pair)
	// would show up as one of these going to zero.
	for _, tc := range []struct {
		product, version string
		wantAtLeast      int
	}{
		{"confluence", "8.3.0", 1},
		{"jira", "9.4.10", 1},
		{"keycloak", "20.0.0", 1},
		{"postgresql", "14.0", 1},
	} {
		if got := len(idx.Lookup(tc.product, tc.version)); got < tc.wantAtLeast {
			t.Errorf("%s %s: got %d findings, want at least %d", tc.product, tc.version, got, tc.wantAtLeast)
		}
	}

	// An unmapped product must still find nothing across 25 years of
	// real data, the same filtering guarantee the small synthetic
	// fixture (sample_nvd.json) already checks in isolation.
	if got := idx.Lookup("widget", "1.0.0"); len(got) != 0 {
		t.Errorf("got %d findings for an unmapped product, want 0", len(got))
	}
}
