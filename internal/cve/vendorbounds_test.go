// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"path/filepath"
	"testing"
)

// testdata/nvd_minio_pfsense.json is four real NVD records, trimmed to
// the fields LoadNVD reads: three MinIO CVEs bounded by release
// timestamps ("2025-10-15t17-29-55z") and pfSense's CVE-2022-29273, which
// carries a Community Edition range and a Plus one ("< 22.05") under the
// same CPE.
func vendorBoundsIDs(t *testing.T, product, raw string, extra map[string]string) map[string]bool {
	t.Helper()
	idx, err := LoadNVD(filepath.Join("testdata", "nvd_minio_pfsense.json"))
	if err != nil {
		t.Fatalf("LoadNVD: %v", err)
	}
	p, v, e, ok := Subject(product, raw, extra)
	if !ok {
		t.Fatalf("Subject(%q, %q) gave no lookup", product, raw)
	}
	ids := map[string]bool{}
	for _, f := range idx.Lookup(p, v, e) {
		ids[f.AdvisoryID] = true
	}
	return ids
}

func TestLookupMinIOTimestampBounds(t *testing.T) {
	for _, tc := range []struct {
		release string
		want    map[string]bool
	}{
		// The last community release: inside 39414's inclusive bound and
		// 33322's range, past 25812's fix.
		{"RELEASE.2025-10-15T17-29-55Z", map[string]bool{"CVE-2026-39414": true, "CVE-2026-33322": true}},
		{"RELEASE.2023-01-01T00-00-00Z", map[string]bool{"CVE-2026-39414": true, "CVE-2026-33322": true, "CVE-2023-25812": true}},
		{"RELEASE.2022-01-01T00-00-00Z", map[string]bool{"CVE-2026-39414": true, "CVE-2023-25812": true}},
		{"RELEASE.2026-03-17T21-25-16Z", map[string]bool{}},
	} {
		got := vendorBoundsIDs(t, "minio", tc.release, nil)
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %v, want %v", tc.release, got, tc.want)
			continue
		}
		for id := range tc.want {
			if !got[id] {
				t.Errorf("%s: got %v, want %v", tc.release, got, tc.want)
			}
		}
	}
}

func TestLookupPfSenseSkipsPlusRange(t *testing.T) {
	if got := vendorBoundsIDs(t, "pfsense", "2.7.2-RELEASE", nil); got["CVE-2022-29273"] {
		t.Error("CVE-2022-29273's Plus range (< 22.05) must not match CE 2.7.2")
	}
	if got := vendorBoundsIDs(t, "pfsense", "2.6.0-RELEASE", nil); !got["CVE-2022-29273"] {
		t.Error("CVE-2022-29273 must match CE 2.6.0 (its community range is <= 2.6.0)")
	}
}

func TestCleanVersionPartsMinIOTimestamp(t *testing.T) {
	for in, want := range map[string]string{
		"2025-10-15t17-29-55z": "2025.10.15.17.29.55",
		"2023-03-13T19-46-17Z": "2023.3.13.19.46.17",
	} {
		got, ok := cleanVersionParts(in)
		if !ok || joinParts(got) != want {
			t.Errorf("cleanVersionParts(%q) = %v, %v; want %s", in, got, ok, want)
		}
	}
	for _, in := range []string{"2015-04-01", "2025-10-15T17-29-55", "RELEASE.2025-10-15T17-29-55Z"} {
		if _, ok := cleanVersionParts(in); ok {
			t.Errorf("cleanVersionParts(%q) accepted a non-timestamp bound", in)
		}
	}
	r, ok := parseBDUVersion("от 2022-07-24t01-54-52z до 2026-04-14t21-32-45z")
	if !ok || r.String() == "" {
		t.Fatalf("parseBDUVersion of a MinIO timestamp range: %v %v", r, ok)
	}
}

// testdata/nvd_jenkins.json is two real NVD records, each with an "lts"
// range and an unmarked weekly one: CVE-2026-70427 (fixed in 2.576 and
// LTS 2.568.2) and CVE-2026-84645 (2.580, LTS 2.568.3).
func TestLookupJenkinsKeepsReleaseLinesApart(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    map[string]bool
	}{
		// Fixed LTS: inside both weekly ranges by number alone.
		{"2.568.3", map[string]bool{}},
		{"2.568.2", map[string]bool{"CVE-2026-84645": true}},
		{"2.568.1", map[string]bool{"CVE-2026-84645": true, "CVE-2026-70427": true}},
		{"2.580", map[string]bool{}},
		{"2.579", map[string]bool{"CVE-2026-84645": true}},
		{"2.575", map[string]bool{"CVE-2026-84645": true, "CVE-2026-70427": true}},
	} {
		idx, err := LoadNVD(filepath.Join("testdata", "nvd_jenkins.json"))
		if err != nil {
			t.Fatal(err)
		}
		p, v, e, _ := Subject("jenkins", tc.version, nil)
		got := map[string]bool{}
		for _, f := range idx.Lookup(p, v, e) {
			got[f.AdvisoryID] = true
		}
		if len(got) != len(tc.want) {
			t.Errorf("jenkins %s: got %v, want %v", tc.version, got, tc.want)
			continue
		}
		for id := range tc.want {
			if !got[id] {
				t.Errorf("jenkins %s: got %v, want %v", tc.version, got, tc.want)
			}
		}
	}
}
