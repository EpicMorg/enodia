// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"path/filepath"
	"testing"
)

// testdata/atlassian_sample.json is Atlassian's real vuln-transparency
// export (/v1/products), trimmed to Confluence (Data Center and Server)
// and Jira Software Data Center, every release kept but only five CVEs'
// entries: CVE-2023-22515 (listed at every affected 8.5 release),
// CVE-2025-59343 (sparse: "8.5.0 AFFECTED", "8.5.10 FIXED"),
// CVE-2025-11226 (affected 9.3 with no 9.3 fix), CVE-2024-21672
// (Confluence-only) and CVE-2023-45133 (Jira, never listed for 10.3).
func loadAtlassianSample(t *testing.T) *Index {
	t.Helper()
	idx, err := LoadAtlassian(filepath.Join("testdata", "atlassian_sample.json"))
	if err != nil {
		t.Fatalf("LoadAtlassian: %v", err)
	}
	return idx
}

func atlassianFinding(fs []Finding, id string) *Finding {
	for i := range fs {
		if fs[i].AdvisoryID == id {
			return &fs[i]
		}
	}
	return nil
}

func TestLoadAtlassianRanges(t *testing.T) {
	idx := loadAtlassianSample(t)
	for _, tc := range []struct {
		product, version, cve string
		want                  bool
		fixed                 string
	}{
		{"confluence", "8.5.1", "CVE-2023-22515", true, "8.5.2"},
		{"confluence", "8.5.2", "CVE-2023-22515", false, ""},
		// Not listed for 8.5.5 at all, but inside 8.5.0..8.5.10.
		{"confluence", "8.5.5", "CVE-2025-59343", true, "8.5.10"},
		{"confluence", "8.5.10", "CVE-2025-59343", false, ""},
		{"confluence", "9.3.4", "CVE-2025-11226", true, ""},
		{"confluence", "9.2.14", "CVE-2025-11226", false, ""},
		{"jira", "10.1.1", "CVE-2023-45133", true, ""},
		// Listed at 10.1.1 and fixed in 11.3.10, but never for 10.3.
		{"jira", "10.3.26", "CVE-2023-45133", false, ""},
		{"jira", "11.3.10", "CVE-2023-45133", false, ""},
	} {
		f := atlassianFinding(idx.Lookup(tc.product, tc.version, ""), tc.cve)
		if (f != nil) != tc.want {
			t.Errorf("%s %s: %s found = %v, want %v", tc.product, tc.version, tc.cve, f != nil, tc.want)
			continue
		}
		if f != nil && f.FixedVersion != tc.fixed {
			t.Errorf("%s %s: %s fixed in %q, want %q", tc.product, tc.version, tc.cve, f.FixedVersion, tc.fixed)
		}
	}
	f := atlassianFinding(idx.Lookup("confluence", "8.5.1", ""), "CVE-2023-22515")
	if f.Source != atlassianSource || f.CVSS.Score != 10 || f.AdvisoryURL == "" {
		t.Errorf("CVE-2023-22515 finding = %+v", f)
	}
}

// A BDU entry filing a Confluence CVE under Jira (as BDU really does for
// CVE-2024-21672) is dropped for a Jira release Atlassian lists, and kept
// for one it doesn't.
func TestAtlassianOverridesOnlyListedReleases(t *testing.T) {
	r, _ := parseBDUVersion("от 7.19.0 до 19.07.18")
	bdu := &Index{byProduct: map[string][]Finding{"jira": {{
		Source: "bdu", AdvisoryID: "BDU:2024-00702", CVEIDs: []string{"CVE-2024-21672"}, rng: r,
	}}}}
	idx := MergeIndex(bdu, loadAtlassianSample(t))
	if f := atlassianFinding(idx.Lookup("jira", "10.3.26", ""), "BDU:2024-00702"); f != nil {
		t.Error("BDU's CVE-2024-21672 must not survive for Jira 10.3.26, which Atlassian lists without it")
	}
	if f := atlassianFinding(idx.Lookup("jira", "10.3.99", ""), "BDU:2024-00702"); f == nil {
		t.Error("a release Atlassian hasn't listed must keep BDU's finding")
	}
}
