// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"path/filepath"
	"sort"
	"testing"
)

func TestSubject(t *testing.T) {
	cases := []struct {
		name                       string
		product, version           string
		extra                      map[string]string
		wantProduct, wantVer, want string
		wantOK                     bool
	}{
		{"openssh bare", "ssh", "OpenSSH_10.3", nil, "openssh", "10.3", "", true},
		{"openssh portable with distro comment", "ssh", "OpenSSH_9.6p1 Ubuntu-3ubuntu13.18", nil, "openssh", "9.6p1", "", true},
		{"dropbear", "ssh", "dropbear_2022.83", nil, "dropbear", "2022.83", "", true},
		{"some other ssh stack gets no lookup", "ssh", "ROSSSH", nil, "", "", "", false},
		{"unknown implementation with underscore", "ssh", "libssh_0.10.6", nil, "", "", "", false},
		{"gitlab ee via Extra", "gitlab", "19.2.2-ee", map[string]string{"enterprise": "true"}, "gitlab", "19.2.2", "enterprise", true},
		{"gitlab ce via Extra wins over suffix", "gitlab", "19.2.2-ee", map[string]string{"enterprise": "false"}, "gitlab", "19.2.2", "community", true},
		{"gitlab edition from suffix alone", "gitlab", "19.2.2-ce", nil, "gitlab", "19.2.2", "community", true},
		{"gitlab edition unknown", "gitlab", "19.2.2", nil, "gitlab", "19.2.2", "", true},
		{"everything else is identity", "jira", "10.3.2", nil, "jira", "10.3.2", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, v, e, ok := Subject(c.product, c.version, c.extra)
			if p != c.wantProduct || v != c.wantVer || e != c.want || ok != c.wantOK {
				t.Fatalf("Subject(%q, %q, %v) = (%q, %q, %q, %v), want (%q, %q, %q, %v)",
					c.product, c.version, c.extra, p, v, e, ok, c.wantProduct, c.wantVer, c.want, c.wantOK)
			}
		})
	}
}

// testdata/nvd_gitlab.json is the nine real NVD records whose ranges
// contain GitLab 19.2.2, extracted from the full 2002-2026 yearly exports
// and trimmed to the fields LoadNVD reads. Five of the nine are
// Enterprise-only in the real data — which is the whole reason edition
// matching exists.
func gitlabIDs(t *testing.T, edition string) []string {
	t.Helper()
	idx, err := LoadNVD(filepath.Join("testdata", "nvd_gitlab.json"))
	if err != nil {
		t.Fatalf("LoadNVD: %v", err)
	}
	seen := map[string]bool{}
	for _, f := range idx.Lookup("gitlab", "19.2.2", edition) {
		seen[f.AdvisoryID] = true
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func TestLookupGitLabCommunityEditionSkipsEnterpriseOnly(t *testing.T) {
	got := gitlabIDs(t, "community")
	want := []string{"CVE-2026-19478", "CVE-2026-19650", "CVE-2026-77801", "CVE-2026-85706"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestLookupGitLabEnterpriseEditionSeesAll(t *testing.T) {
	if got := gitlabIDs(t, "enterprise"); len(got) != 9 {
		t.Fatalf("got %d distinct CVEs (%v), want all 9", len(got), got)
	}
}

// Unknown edition keeps everything: a false positive to double-check,
// not a silent miss.
func TestLookupGitLabUnknownEditionSeesAll(t *testing.T) {
	if got := gitlabIDs(t, ""); len(got) != 9 {
		t.Fatalf("got %d distinct CVEs (%v), want all 9", len(got), got)
	}
}

// CVE-2026-85706's real 19.2 range is 19.2.0 up to (not including)
// 19.2.6 — the first fixed release must be clean of it.
func TestLookupGitLabFixedReleaseIsClean(t *testing.T) {
	idx, err := LoadNVD(filepath.Join("testdata", "nvd_gitlab.json"))
	if err != nil {
		t.Fatalf("LoadNVD: %v", err)
	}
	for _, f := range idx.Lookup("gitlab", "19.2.6", "community") {
		if f.AdvisoryID == "CVE-2026-85706" {
			t.Fatal("CVE-2026-85706 must not match 19.2.6, its real fix version")
		}
	}
	found := false
	for _, f := range idx.Lookup("gitlab", "19.1.7", "community") {
		if f.AdvisoryID == "CVE-2026-85706" {
			found = true
		}
	}
	if !found {
		t.Fatal("CVE-2026-85706 must match 19.1.7 (its real 18.7.0 to <19.1.8 range)")
	}
}

// A probed version with a letter suffix compares by its numeric spine:
// OpenSSH's real NVD bounds are plain ("9.8"), its banner is "9.6p1".
func TestMatchesUsesNumericSpineOfProbedVersion(t *testing.T) {
	rng, ok := parseNVDRange(nvdCPEMatch{Criteria: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", VersionEndExcluding: "9.8"})
	if !ok {
		t.Fatal("parseNVDRange rejected a plain bound")
	}
	f := Finding{rng: rng}
	if !f.Matches("9.6p1") {
		t.Fatal("9.6p1 should fall before 9.8")
	}
	if f.Matches("9.8p1") {
		t.Fatal("9.8p1 is 9.8 by its numeric spine, excluded by versionEndExcluding")
	}
}
