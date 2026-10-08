// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// mariadb_community_sample.md is the head of MariaDB's real
// community-server.md table plus seven of its real rows, verbatim:
// CVE-2026-32710 and -35549 (fixed in 12.2.2/11.8.6/11.4.10 only — 10.11
// never had the code), -3494 (fixed in every live series down to 10.6),
// -92262 (12.3.3 ... 10.6.28, the row that dates 10.11 and 10.6 as still
// maintained in 2026-08), CVE-2025-30722 (whose 10.5.29 is the last 10.5
// fix in this sample, dated 2025-05-08; two of its fixes carry no date),
// CVE-2023-52971 (no dates at all) and CVE-2012-0496 (a whole "5.5"
// series, no release).
func loadMariaDBSample(t *testing.T) *Index {
	t.Helper()
	idx, err := LoadMariaDB(filepath.Join("testdata", "mariadb_community_sample.md"))
	if err != nil {
		t.Fatalf("LoadMariaDB: %v", err)
	}
	return idx
}

func cveIDsOf(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		for _, id := range f.CVEIDs {
			if !slices.Contains(out, id) {
				out = append(out, id)
			}
		}
	}
	slices.Sort(out)
	return out
}

func findingFor(fs []Finding, id string) (Finding, bool) {
	for _, f := range fs {
		if slices.Contains(f.CVEIDs, id) {
			return f, true
		}
	}
	return Finding{}, false
}

func TestMariaDBOwnSeriesFix(t *testing.T) {
	idx := loadMariaDBSample(t)

	got := idx.Lookup("mariadb", "11.4.9", "")
	f, ok := findingFor(got, "CVE-2026-32710")
	if !ok {
		t.Fatalf("11.4.9: CVE-2026-32710 not flagged; got %v", cveIDsOf(got))
	}
	if f.Source != "mariadb" || f.FixedVersion != "11.4.10" || f.CVSS.Score != 8.6 || f.CVSS.Severity != "HIGH" {
		t.Fatalf("got %+v", f)
	}

	// The series' own fix closes it, and a newer series' bound doesn't
	// reopen it the way BDU's open-ended ranges do.
	if got := idx.Lookup("mariadb", "11.4.10", ""); slices.Contains(cveIDsOf(got), "CVE-2026-32710") {
		t.Fatal("11.4.10 is 11.4's own fix for CVE-2026-32710")
	}
}

func TestMariaDBMaintainedSeriesWithoutFixIsUnaffected(t *testing.T) {
	idx := loadMariaDBSample(t)
	// 10.11 was still getting fixes (10.11.16 in 2026-02, 10.11.19 in
	// 2026-08) when CVE-2026-32710 was fixed elsewhere, and got none for
	// it: MariaDB fixes every live series at once, so 10.11 isn't affected.
	got := idx.Lookup("mariadb", "10.11.8", "")
	if ids := cveIDsOf(got); slices.Contains(ids, "CVE-2026-32710") || slices.Contains(ids, "CVE-2026-35549") {
		t.Fatalf("10.11.8: got %v, want neither CVE-2026-32710 nor -35549", ids)
	}
	if !slices.Contains(cveIDsOf(got), "CVE-2026-3494") {
		t.Fatalf("10.11.8: CVE-2026-3494 (fixed in 10.11.16) not flagged; got %v", cveIDsOf(got))
	}
	if got := idx.Lookup("mariadb", "10.11.19", ""); len(got) != 0 {
		t.Fatalf("10.11.19: got %v, want nothing", cveIDsOf(got))
	}
}

func TestMariaDBEndedSeriesIsFlaggedWithUpgradeTarget(t *testing.T) {
	idx := loadMariaDBSample(t)
	// 10.5's last fix in the table is 10.5.29 (2025-05-08); CVE-2026-32710
	// was first fixed 2026-02-04, after 10.5 had ended.
	got := idx.Lookup("mariadb", "10.5.29", "")
	f, ok := findingFor(got, "CVE-2026-32710")
	if !ok {
		t.Fatalf("10.5.29: CVE-2026-32710 not flagged; got %v", cveIDsOf(got))
	}
	if f.FixedVersion != "11.4.10" || f.FixStatus == "" {
		t.Fatalf("got FixedVersion %q FixStatus %q, want 11.4.10 and a no-fix note", f.FixedVersion, f.FixStatus)
	}
	// Its own series' fix still counts for a CVE 10.5 did get.
	if slices.Contains(cveIDsOf(got), "CVE-2025-30722") {
		t.Fatal("10.5.29 is 10.5's own fix for CVE-2025-30722")
	}
}

func TestMariaDBRowsWithoutDatesOrReleases(t *testing.T) {
	idx := loadMariaDBSample(t)
	// CVE-2023-52971 has fixes but no dates: own-series fixes still apply.
	if !slices.Contains(cveIDsOf(idx.Lookup("mariadb", "10.11.11", "")), "CVE-2023-52971") {
		t.Fatal("10.11.11: CVE-2023-52971 (fixed in 10.11.12) not flagged")
	}
	// A whole-series entry ("[5.5]") gives no bound, so it matches nothing
	// and isn't counted as vendor-known either.
	if idx.vendorCVEs["mariadb"]["CVE-2012-0496"] {
		t.Fatal("CVE-2012-0496 has no release to compare against")
	}
}

// The point of merging: where the vendor's table knows a CVE, its verdict
// replaces BDU's and NVD's open-ended per-series ranges; where it doesn't,
// they stand.
func TestMariaDBOverridesOtherSourcesOnKnownCVEs(t *testing.T) {
	vendor := loadMariaDBSample(t)
	other := &Index{byProduct: map[string][]Finding{"mariadb": {
		// BDU's real shape for CVE-2026-32710: "до 11.8.6", no lower bound.
		{Source: "bdu", AdvisoryID: "BDU:2026-03808", CVEIDs: []string{"CVE-2026-32710"}, rng: versionRange{Hi: []int{11, 8, 6}}},
		{Source: "nvd", AdvisoryID: "CVE-2099-0001", CVEIDs: []string{"CVE-2099-0001"}, rng: versionRange{Hi: []int{11, 0}}},
		{Source: "bdu", AdvisoryID: "BDU:2099-00001", rng: versionRange{Hi: []int{11, 0}}},
	}}}
	idx := MergeIndex(other, vendor)

	got := idx.Lookup("mariadb", "10.11.19", "")
	ids := cveIDsOf(got)
	if slices.Contains(ids, "CVE-2026-32710") {
		t.Fatalf("10.11.19: BDU's CVE-2026-32710 kept though MariaDB says 10.11 is unaffected: %v", ids)
	}
	if !slices.Contains(ids, "CVE-2099-0001") {
		t.Fatalf("10.11.19: NVD-only CVE dropped: %v", ids)
	}
	if !slices.ContainsFunc(got, func(f Finding) bool { return f.AdvisoryID == "BDU:2099-00001" }) {
		t.Fatal("BDU entry with no CVE id dropped")
	}

	// When MariaDB flags it too, the other source's finding stays alongside.
	got = idx.Lookup("mariadb", "11.4.9", "")
	var sources []string
	for _, f := range got {
		if slices.Contains(f.CVEIDs, "CVE-2026-32710") {
			sources = append(sources, f.Source)
		}
	}
	slices.Sort(sources)
	if !slices.Equal(sources, []string{"bdu", "mariadb"}) {
		t.Fatalf("11.4.9: CVE-2026-32710 sources %v, want [bdu mariadb]", sources)
	}
}

func TestLoadMariaDBRejectsOtherFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.md")
	if err := os.WriteFile(path, []byte("# Not the table\n\n| a | b |\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMariaDB(path); err == nil {
		t.Fatal("expected an error for a file with no CVE rows")
	}
}
