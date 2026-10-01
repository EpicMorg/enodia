// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// testdata/alpine_v3.20_{main,community}.json are Alpine's real v3.20
// secdb files cut down to a few packages: avahi and busybox (both with a
// "0" never-affected entry; busybox also cites "ALPINE-13661"), musl,
// zlib, and community's go.
func loadAlpineSample(t *testing.T) *Index {
	t.Helper()
	dir := t.TempDir()
	for _, n := range []string{"alpine_v3.20_main.json", "alpine_v3.20_community.json"} {
		raw, err := os.ReadFile(filepath.Join("testdata", n))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, n), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	idx, err := LoadAlpineSecdb(dir)
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

// The versions alpine:3.20.0 shipped, confirmed live: musl 1.2.5-r0 and
// busybox 1.36.1-r28 — `apk upgrade` there moves them to 1.2.5-r3 and
// 1.36.1-r31, exactly the FixedVersion secdb gives.
func TestLookupAlpine(t *testing.T) {
	idx := loadAlpineSample(t)
	got := idx.LookupPackages(PackageQuery{Product: "alpine-linux", Version: "3.20.0",
		Packages: map[string]string{"musl": "1.2.5-r0", "busybox": "1.36.1-r28", "zlib": "1.3.1-r1", "go": "1.22.7-r0", "avahi": "0.8-r17"}})
	if len(got) != 3 {
		t.Fatalf("got %+v, want busybox, musl, zlib", got)
	}
	busybox, musl := got[0], got[1]
	if busybox.MatchedName != "busybox" || busybox.FixedVersion != "1.36.1-r31" || len(busybox.CVEIDs) != 4 {
		t.Errorf("busybox = %+v", busybox)
	}
	if musl.FixedVersion != "1.2.5-r3" || !slices.Equal(musl.CVEIDs, []string{"CVE-2025-26519", "CVE-2026-6042", "CVE-2026-40200"}) ||
		musl.Source != "alpine" || musl.AdvisoryURL != "https://security.alpinelinux.org/srcpkg/musl" {
		t.Errorf("musl = %+v", musl)
	}
}

// "0" means never affected; a fix citing no CVE ("ALPINE-13661") keeps
// only the CVEs next to it.
func TestLookupAlpineZeroAndNonCVE(t *testing.T) {
	idx := loadAlpineSample(t)
	got := idx.LookupPackages(PackageQuery{Product: "alpine-linux", Version: "3.20.3", Packages: map[string]string{"busybox": "1.35.0-r6"}})
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	for _, id := range got[0].CVEIDs {
		if id == "CVE-2021-42373" || id == "ALPINE-13661" {
			t.Errorf("got %s in %v", id, got[0].CVEIDs)
		}
	}
	if !slices.Contains(got[0].CVEIDs, "CVE-2022-28391") {
		t.Errorf("CVE-2022-28391 (next to ALPINE-13661) missing from %v", got[0].CVEIDs)
	}
}

func TestLookupAlpineOtherBranch(t *testing.T) {
	idx := loadAlpineSample(t)
	for _, v := range []string{"3.22.1", "edge", ""} {
		if got := idx.LookupPackages(PackageQuery{Product: "alpine-linux", Version: v, Packages: map[string]string{"musl": "1.2.5-r0"}}); got != nil {
			t.Errorf("%q: got %+v", v, got)
		}
	}
}

func TestLoadAlpineSecdbRejectsWrongFile(t *testing.T) {
	if _, err := LoadAlpineSecdb("testdata/debian_tracker_sample.json"); err == nil {
		t.Fatal("expected an error for a non-secdb file")
	}
}
