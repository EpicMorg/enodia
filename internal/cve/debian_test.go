// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// testdata/debian_tracker_sample.json is ten real entries cut from the
// Debian Security Tracker's JSON export (descriptions truncated, releases
// other than bookworm/trixie dropped): for openssl and linux, CVEs fixed
// in trixie, never affecting it ("0"), and still open.
func loadTrackerSample(t *testing.T) *Index {
	t.Helper()
	idx, err := LoadDebianTracker("testdata/debian_tracker_sample.json")
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

func TestLookupPackagesFixedButNotInstalled(t *testing.T) {
	idx := loadTrackerSample(t)
	got := idx.LookupPackages(PackageQuery{Product: "debian", Packages: map[string]string{"openssl": "3.5.7-1~deb13u2", "linux": "6.12.111-1", "bash": "5.2.37-2"}, Extra: map[string]string{"codename": "trixie", "kernel": "6.12.74-2"}})
	if len(got) != 2 {
		t.Fatalf("got %d findings, want linux and openssl: %+v", len(got), got)
	}

	linux, openssl := got[0], got[1]
	if linux.AdvisoryID != "linux" || openssl.AdvisoryID != "openssl" {
		t.Fatalf("got %q, %q, want linux, openssl (sorted by package)", linux.AdvisoryID, openssl.AdvisoryID)
	}
	// Fixed in 6.12.85-1 and 6.12.111-1: the newest is what clears both.
	if want := []string{"CVE-2024-14027", "CVE-2024-52560", "CVE-2024-58094", "CVE-2025-21709"}; !slices.Equal(linux.CVEIDs, want) {
		t.Errorf("linux CVEs = %v, want %v (open ones never included)", linux.CVEIDs, want)
	}
	if linux.FixedVersion != "6.12.111-1" || linux.InstalledVersion != "6.12.74-2" || linux.Source != "debian" {
		t.Errorf("linux = %+v", linux)
	}
	// CVE-2009-* are "0": never affected trixie.
	if want := []string{"CVE-2026-35189", "CVE-2026-35191"}; !slices.Equal(openssl.CVEIDs, want) {
		t.Errorf("openssl CVEs = %v, want %v", openssl.CVEIDs, want)
	}
	if openssl.FixedVersion != "3.5.7-1~deb13u3" || openssl.RangeText != "< 3.5.7-1~deb13u3" {
		t.Errorf("openssl = %+v", openssl)
	}
}

func TestLookupPackagesUpToDateHasNoFindings(t *testing.T) {
	idx := loadTrackerSample(t)
	got := idx.LookupPackages(PackageQuery{Product: "debian", Packages: map[string]string{"openssl": "3.5.7-1~deb13u3", "linux": "6.12.111-1"}, Extra: map[string]string{"codename": "trixie"}})
	if len(got) != 0 {
		t.Fatalf("got %+v, want none", got)
	}
}

// The same packages on bookworm see bookworm's own statuses: its
// CVE-2024-58094 fix is 6.1.187-1, and its CVE-2024-52560 is still open.
func TestLookupPackagesUsesTheHostsRelease(t *testing.T) {
	idx := loadTrackerSample(t)
	got := idx.LookupPackages(PackageQuery{Product: "debian", Packages: map[string]string{"linux": "6.1.180-1"}, Extra: map[string]string{"codename": "bookworm", "kernel": "6.1.180-1"}})
	if len(got) != 1 || !slices.Equal(got[0].CVEIDs, []string{"CVE-2024-58094"}) || got[0].FixedVersion != "6.1.187-1" {
		t.Fatalf("got %+v", got)
	}
}

// The running kernel, not the oldest installed linux-* package, is what
// is exposed: old headers left behind must not flag a rebooted host, and
// a newer kernel installed but not booted must not hide a vulnerable one.
func TestLookupPackagesRunningKernelWins(t *testing.T) {
	idx := loadTrackerSample(t)
	pkgs := map[string]string{"linux": "6.12.74-2"}

	got := idx.LookupPackages(PackageQuery{Product: "debian", Packages: pkgs, Extra: map[string]string{"codename": "trixie", "kernel": "6.12.111-1"}})
	if len(got) != 0 {
		t.Fatalf("running 6.12.111-1: got %+v, want none", got)
	}
	if pkgs["linux"] != "6.12.74-2" {
		t.Fatal("LookupPackages must not modify the observation's own Packages")
	}

	got = idx.LookupPackages(PackageQuery{Product: "debian", Packages: map[string]string{"linux": "6.12.111-1"}, Extra: map[string]string{"codename": "trixie", "kernel": "6.12.85-1"}})
	if len(got) != 1 || got[0].InstalledVersion != "6.12.85-1" || len(got[0].CVEIDs) != 2 {
		t.Fatalf("running 6.12.85-1: got %+v, want the two CVEs fixed in 6.12.111-1", got)
	}
}

func TestLookupPackagesNoDataIsNil(t *testing.T) {
	idx := loadTrackerSample(t)
	pkgs := map[string]string{"linux": "6.12.74-2"}
	for name, got := range map[string][]Finding{
		"not debian":       idx.LookupPackages(PackageQuery{Product: "ubuntu", Packages: pkgs, Extra: map[string]string{"codename": "trixie"}}),
		"unknown codename": idx.LookupPackages(PackageQuery{Product: "debian", Packages: pkgs, Extra: map[string]string{"codename": "bullseye"}}),
		"no packages":      idx.LookupPackages(PackageQuery{Product: "debian", Packages: nil, Extra: map[string]string{"codename": "trixie"}}),
		"nil index":        (*Index)(nil).LookupPackages(PackageQuery{Product: "debian", Packages: pkgs, Extra: map[string]string{"codename": "trixie"}}),
		"no tracker":       (&Index{}).LookupPackages(PackageQuery{Product: "debian", Packages: pkgs, Extra: map[string]string{"codename": "trixie"}}),
	} {
		if got != nil {
			t.Errorf("%s: got %+v", name, got)
		}
	}
}

// Severity is the tracker's own urgency word — the most urgent one among
// the package's CVEs — never "not yet assigned", which is no rating.
func TestLookupPackagesSeverityIsMostUrgent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tracker.json")
	if err := os.WriteFile(path, []byte(`{"curl": {
		"CVE-2026-1": {"releases": {"trixie": {"status": "resolved", "fixed_version": "8.14.1-2+deb13u1", "urgency": "low"}}},
		"CVE-2026-2": {"releases": {"trixie": {"status": "resolved", "fixed_version": "8.14.1-2+deb13u2", "urgency": "medium"}}},
		"CVE-2026-3": {"releases": {"trixie": {"status": "resolved", "fixed_version": "8.14.1-2+deb13u2", "urgency": "not yet assigned"}}}
	}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	idx, err := LoadDebianTracker(path)
	if err != nil {
		t.Fatal(err)
	}
	got := idx.LookupPackages(PackageQuery{Product: "debian", Packages: map[string]string{"curl": "8.14.1-2"}, Extra: map[string]string{"codename": "trixie"}})
	if len(got) != 1 || got[0].Severity != "medium" || len(got[0].CVEIDs) != 3 {
		t.Fatalf("got %+v", got)
	}
}

func TestLoadDebianTrackerRejectsWrongFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tracker.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDebianTracker(path); err == nil {
		t.Fatal("expected an error for an empty export")
	}
	if _, err := LoadDebianTracker("testdata/sample_nvd.json"); err == nil {
		t.Fatal("expected an error for an NVD file")
	}
}

// MergeIndex keeps the tracker whichever side it came in on, so the
// pipeline's BDU+NVD+Debian merge order doesn't matter.
func TestMergeIndexKeepsDebianTracker(t *testing.T) {
	deb := loadTrackerSample(t)
	merged := MergeIndex(&Index{byProduct: map[string][]Finding{}}, deb)
	got := merged.LookupPackages(PackageQuery{Product: "debian", Packages: map[string]string{"linux": "6.12.74-2"}, Extra: map[string]string{"codename": "trixie", "kernel": "6.12.74-2"}})
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
}

// A Proxmox VE host is Debian with its own kernel: `uname -v` says "PMX",
// not "Debian", so there's no kernel fact — and Debian's linux source is
// only there as linux-libc-dev headers. That must not turn into hundreds
// of kernel CVEs.
func TestLookupPackagesNoDebianKernelMeansNoLinuxFindings(t *testing.T) {
	idx := loadTrackerSample(t)
	got := idx.LookupPackages(PackageQuery{Product: "debian", Packages: map[string]string{"linux": "6.12.74-2"}, Extra: map[string]string{"codename": "trixie"}})
	if len(got) != 0 {
		t.Fatalf("got %+v, want none", got)
	}
}
