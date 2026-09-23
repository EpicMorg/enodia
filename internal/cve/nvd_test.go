// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"archive/zip"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// testdata/sample_nvd.json wraps the real CVE-2023-22515 NVD record (the
// same one BDU's own sample.xml carries, fetched live from
// services.nvd.nist.gov/rest/json/cves/2.0 — see docs/DECISIONS.md D31)
// plus several synthetic entries covering the real per-cpeMatch shapes
// found live: an unmapped product, an open-ended range with no fix yet, an
// exact version embedded directly in the CPE string, a garbage version
// bound, a Rejected CVE that must be skipped entirely despite carrying a
// configuration, and a cpeMatch with no version constraint at all.
func TestLoadNVDFromRawJSON(t *testing.T) {
	idx, err := LoadNVD(filepath.Join("testdata", "sample_nvd.json"))
	if err != nil {
		t.Fatalf("LoadNVD: %v", err)
	}

	// Unlike BDU's overlapping-branch ranges, NVD gives each branch its own
	// lower bound too — 8.3.3 (Atlassian's real fix version) must match
	// none of the three ranges, not two.
	if got := idx.Lookup("confluence", "8.3.3", ""); len(got) != 0 {
		t.Fatalf("got %d findings for 8.3.3, want 0 (NVD's ranges don't overlap across branches)", len(got))
	}
	got := idx.Lookup("confluence", "8.3.0", "")
	if len(got) != 2 { // confluence_data_center and confluence_server, same range
		t.Fatalf("got %d confluence findings for 8.3.0, want 2", len(got))
	}
	for _, f := range got {
		if f.Source != "nvd" {
			t.Errorf("got Source %q, want nvd", f.Source)
		}
		if f.AdvisoryID != "CVE-2023-22515" || len(f.CVEIDs) != 1 || f.CVEIDs[0] != "CVE-2023-22515" {
			t.Errorf("got AdvisoryID %q CVEIDs %+v", f.AdvisoryID, f.CVEIDs)
		}
		if f.Severity != "CRITICAL" {
			t.Errorf("got Severity %q, want CRITICAL", f.Severity)
		}
	}

	if got := idx.Lookup("confluence", "8.5.2", ""); len(got) != 0 {
		t.Fatalf("got %d findings for 8.5.2 (the real fix version), want 0", len(got))
	}
}

func TestLoadNVDFiltersUnmappedProduct(t *testing.T) {
	idx, err := LoadNVD(filepath.Join("testdata", "sample_nvd.json"))
	if err != nil {
		t.Fatalf("LoadNVD: %v", err)
	}
	if got := idx.Lookup("widget", "1.0.0", ""); len(got) != 0 {
		t.Fatalf("got %d findings for an unmapped product, want 0", len(got))
	}
}

func TestLoadNVDOpenEndedRangeHasNoUpperBound(t *testing.T) {
	idx, err := LoadNVD(filepath.Join("testdata", "sample_nvd.json"))
	if err != nil {
		t.Fatalf("LoadNVD: %v", err)
	}
	if got := idx.Lookup("postgresql", "16.0", ""); len(got) != 1 {
		t.Fatalf("got %d findings for postgresql 16.0, want 1 (CVE-2099-00002's lower bound)", len(got))
	}
	if got := idx.Lookup("postgresql", "99.0.0", ""); len(got) != 1 {
		t.Fatalf("got %d findings for postgresql 99.0.0, want 1 (still no known fix)", len(got))
	}
	if got := idx.Lookup("postgresql", "15.9", ""); len(got) != 0 {
		t.Fatalf("got %d findings for postgresql 15.9 (below the stated lower bound), want 0", len(got))
	}
}

func TestLoadNVDLiteralVersionInCriteriaIsExactPoint(t *testing.T) {
	idx, err := LoadNVD(filepath.Join("testdata", "sample_nvd.json"))
	if err != nil {
		t.Fatalf("LoadNVD: %v", err)
	}
	if got := idx.Lookup("postgresql", "9.6.24", ""); len(got) != 1 {
		t.Fatalf("got %d findings for postgresql 9.6.24, want 1 (CVE-2099-00003's exact-point match)", len(got))
	}
	// 9.6.25 is below CVE-2099-00002's 16.0 lower bound and isn't
	// CVE-2099-00003's exact 9.6.24 point either.
	if got := idx.Lookup("postgresql", "9.6.25", ""); len(got) != 0 {
		t.Fatalf("got %d findings for postgresql 9.6.25, want 0", len(got))
	}
}

func TestLoadNVDGarbageVersionBoundIsDropped(t *testing.T) {
	idx, err := LoadNVD(filepath.Join("testdata", "sample_nvd.json"))
	if err != nil {
		t.Fatalf("LoadNVD: %v", err)
	}
	// CVE-2099-00004's only cpeMatch has an unparseable versionEndExcluding
	// ("1.2.3-beta") — the whole entry must be discarded, not partially
	// applied with a zero-value bound. (keycloak's other synthetic entry,
	// CVE-2099-00006, carries no version constraint at all and is dropped
	// too — see TestLoadNVDNoConstraintIsDropped.)
	if got := idx.Lookup("keycloak", "0.0.1", ""); len(got) != 0 {
		t.Fatalf("got %+v, want no keycloak findings at all", got)
	}
}

func TestLoadNVDRejectedCVEIsSkipped(t *testing.T) {
	idx, err := LoadNVD(filepath.Join("testdata", "sample_nvd.json"))
	if err != nil {
		t.Fatalf("LoadNVD: %v", err)
	}
	for _, f := range idx.Lookup("postgresql", "1.0.0", "") {
		if f.AdvisoryID == "CVE-2099-00005" {
			t.Fatalf("a Rejected CVE must never be indexed, even with a well-formed configuration")
		}
	}
}

// A cpeMatch with neither bounds nor a version in its CPE string carries
// no version information at all. Read as "every version", it turned out
// against the real exports to mostly attach 1999-2016 CVEs to current
// releases (docs/DECISIONS.md D33), so it is dropped instead.
func TestLoadNVDNoConstraintIsDropped(t *testing.T) {
	idx, err := LoadNVD(filepath.Join("testdata", "sample_nvd.json"))
	if err != nil {
		t.Fatalf("LoadNVD: %v", err)
	}
	for _, probed := range []string{"0.0.1", "999.999.999"} {
		for _, f := range idx.Lookup("keycloak", probed, "") {
			if f.AdvisoryID == "CVE-2099-00006" {
				t.Fatalf("CVE-2099-00006 (no version constraint at all) must not match %q", probed)
			}
		}
	}
}

func TestLoadNVDFromDirectoryMergesEveryFile(t *testing.T) {
	dir := t.TempDir()
	copyFile(t, filepath.Join("testdata", "sample_nvd.json"), filepath.Join(dir, "nvdcve-2.0-2023.json"))

	idx, err := LoadNVD(dir)
	if err != nil {
		t.Fatalf("LoadNVD: %v", err)
	}
	if got := idx.Lookup("confluence", "8.3.0", ""); len(got) != 2 {
		t.Fatalf("got %d findings, want the same result as loading the file directly", len(got))
	}
}

func TestLoadNVDFromGzip(t *testing.T) {
	dir := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("testdata", "sample_nvd.json"))
	if err != nil {
		t.Fatal(err)
	}
	gzPath := filepath.Join(dir, "nvdcve-2.0-2023.json.gz")
	f, err := os.Create(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	if _, err := gw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	idx, err := LoadNVD(gzPath)
	if err != nil {
		t.Fatalf("LoadNVD: %v", err)
	}
	if got := idx.Lookup("confluence", "8.3.0", ""); len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
}

func TestLoadNVDFromZip(t *testing.T) {
	dir := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("testdata", "sample_nvd.json"))
	if err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(dir, "nvdcve-2.0-2023.json.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("nvdcve-2.0-2023.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	idx, err := LoadNVD(zipPath)
	if err != nil {
		t.Fatalf("LoadNVD: %v", err)
	}
	if got := idx.Lookup("confluence", "8.3.0", ""); len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
}

func TestLoadNVDMissingPathErrors(t *testing.T) {
	if _, err := LoadNVD(filepath.Join("testdata", "does-not-exist.json")); err == nil {
		t.Fatal("expected an error for a missing path")
	}
}

func TestLoadNVDEmptyDirectoryErrors(t *testing.T) {
	if _, err := LoadNVD(t.TempDir()); err == nil {
		t.Fatal("expected an error for a directory with no .json/.json.gz/.json.zip files")
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
