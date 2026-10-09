// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"path/filepath"
	"testing"
)

// testdata/postgresql/ is the project's real security pages, trimmed to a
// few rows: main.html (https://www.postgresql.org/support/security/,
// which names only the majors supported today) and 13.html (the page for
// 13, which names 13 too).
func TestLoadPostgreSQL(t *testing.T) {
	idx, err := LoadPostgreSQL(filepath.Join("testdata", "postgresql"))
	if err != nil {
		t.Fatalf("LoadPostgreSQL: %v", err)
	}
	for _, tc := range []struct {
		version, cve string
		want         bool
		fixed        string
	}{
		{"17.10", "CVE-2026-19385", true, "17.11"},
		{"17.11", "CVE-2026-19385", false, ""},
		{"14.24", "CVE-2026-19385", false, ""},
		// 13 had ended: the CVE reaches back to 14, the oldest major then.
		{"13.23", "CVE-2026-19385", true, "14.24"},
		// Named only on 13's own page; merged with the main page's row.
		{"13.18", "CVE-2025-1094", true, "13.19"},
		{"13.19", "CVE-2025-1094", false, ""},
		{"12.20", "CVE-2024-10979", true, "12.21"},
	} {
		f := findingByID(idx.Lookup("postgresql", tc.version, ""), tc.cve)
		if (f != nil) != tc.want {
			t.Errorf("%s: %s found = %v, want %v", tc.version, tc.cve, f != nil, tc.want)
			continue
		}
		if f != nil && f.FixedVersion != tc.fixed {
			t.Errorf("%s: %s fixed in %q, want %q", tc.version, tc.cve, f.FixedVersion, tc.fixed)
		}
	}
	f := findingByID(idx.Lookup("postgresql", "17.10", ""), "CVE-2026-19385")
	if f.CVSS.Score != 8.8 || f.MatchedName != "PostgreSQL client" {
		t.Errorf("CVE-2026-19385 = %+v", f)
	}
}

// BDU's PostgreSQL ranges have no lower bound ("до 18.5"), so they flag
// every older major's latest release; the project's table says those
// majors were fixed on their own branch.
func TestPostgreSQLOverridesBranchlessBDU(t *testing.T) {
	r, _ := parseBDUVersion("до 18.6")
	bdu := &Index{byProduct: map[string][]Finding{"postgresql": {{
		Source: "bdu", AdvisoryID: "BDU:2026-11973", CVEIDs: []string{"CVE-2026-19385"}, rng: r,
	}}}}
	pg, err := LoadPostgreSQL(filepath.Join("testdata", "postgresql", "main.html"))
	if err != nil {
		t.Fatal(err)
	}
	idx := MergeIndex(bdu, pg)
	if f := findingByID(idx.Lookup("postgresql", "17.11", ""), "BDU:2026-11973"); f != nil {
		t.Error("BDU's branchless range must not survive for 17.11, fixed on its own branch")
	}
	// The main page alone doesn't name 13: its verdict doesn't cover it.
	if f := findingByID(idx.Lookup("postgresql", "13.23", ""), "BDU:2026-11973"); f == nil {
		t.Error("a major the table doesn't name must keep BDU's finding")
	}
}

// testdata/nginx_security_advisories.html is nginx's real advisories
// page, trimmed to nine entries.
func TestLoadNginx(t *testing.T) {
	idx, err := LoadNginx(filepath.Join("testdata", "nginx_security_advisories.html"))
	if err != nil {
		t.Fatalf("LoadNginx: %v", err)
	}
	for _, tc := range []struct {
		version, cve string
		want         bool
	}{
		// Vulnerable: 1.29.2-1.31.5; Not vulnerable: 1.31.6+, 1.30.5+
		{"1.31.5", "CVE-2026-90439", true},
		{"1.31.6", "CVE-2026-90439", false},
		{"1.30.4", "CVE-2026-90439", true},
		{"1.30.5", "CVE-2026-90439", false},
		{"1.29.8", "CVE-2026-90439", true}, // an ended branch, never fixed
		{"1.29.1", "CVE-2026-90439", false},
		// Vulnerable: 1.25.0-1.25.5, 1.26.0
		{"1.26.0", "CVE-2024-32760", true},
		{"1.26.1", "CVE-2024-32760", false},
		{"1.25.3", "CVE-2024-32760", true},
		{"1.24.0", "CVE-2024-32760", false},
		// nginx/Windows only.
		{"1.2.0", "CVE-2011-4963", false},
	} {
		f := findingByID(idx.Lookup("nginx", tc.version, ""), tc.cve)
		if (f != nil) != tc.want {
			t.Errorf("%s: %s found = %v, want %v", tc.version, tc.cve, f != nil, tc.want)
		}
	}
	f := findingByID(idx.Lookup("nginx", "1.30.4", ""), "CVE-2026-90439")
	if f.FixedVersion != "1.30.5" || f.Severity != "medium" || f.AdvisoryURL == "" {
		t.Errorf("CVE-2026-90439 = %+v", f)
	}
}
