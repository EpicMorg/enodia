// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// testdata/oval_*.xml are real definitions cut from each vendor's own
// OVAL file, with every test, object, state and variable they reference
// (and descriptions/most CVE references trimmed):
//   - oval_ubuntu_noble.xml: USN-6937-1 (openssl, libssl3t64) and
//     USN-6816-1 (running-kernel checks for four flavours).
//   - oval_rhel9.xml: RHSA-2024:6783 (openssl), RHSA-2023:5363 (nodejs in
//     module stream nodejs:18), RHSA-2022:6595 (non-modular nodejs 16).
//   - oval_oracle9.xml: ELSA-2026-67165-0 (openssl) and ELSA-2026-50075
//     (its FIPS rebuild), each with x86_64 and aarch64 branches.
//   - oval_alma9.xml: ALSA-2024:6783, which carries no <platform>.
//   - oval_rocky9.xml: RLSA-2024:6783, to be refused.
func loadOVALFixture(t *testing.T, names ...string) *Index {
	t.Helper()
	dir := t.TempDir()
	for _, n := range names {
		raw, err := os.ReadFile(filepath.Join("testdata", n))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, n), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	idx, err := LoadOVAL(dir)
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

func TestOVALReleaseFromContent(t *testing.T) {
	idx := loadOVALFixture(t, "oval_ubuntu_noble.xml", "oval_rhel9.xml", "oval_oracle9.xml", "oval_alma9.xml")
	for _, key := range []string{"ubuntu:noble", "rhel:9", "oracle-linux:9", "almalinux:9"} {
		if idx.oval[key] == nil {
			t.Errorf("no release %s loaded; have %v", key, slices.Sorted(maps.Keys(idx.oval)))
		}
	}
}

func TestOVALRejectsRockysOwnFile(t *testing.T) {
	_, err := LoadOVAL("testdata/oval_rocky9.xml")
	if err == nil || !strings.Contains(err.Error(), "rhel-9.oval.xml") {
		t.Fatalf("got %v, want a refusal pointing at rhel-9.oval.xml", err)
	}
}

func TestOVALUbuntuPackages(t *testing.T) {
	idx := loadOVALFixture(t, "oval_ubuntu_noble.xml")
	q := PackageQuery{Product: "ubuntu", Version: "24.04", Extra: map[string]string{"codename": "noble"},
		Packages: map[string]string{"libssl3t64": "3.0.13-0ubuntu3.1", "openssl": "3.0.13-0ubuntu3.2", "bash": "5.2.21-2ubuntu4"}}
	got := idx.LookupPackages(q)
	if len(got) != 1 {
		t.Fatalf("got %+v, want libssl3t64 only (openssl is already at the fix)", got)
	}
	f := got[0]
	if f.MatchedName != "libssl3t64" || f.FixedVersion != "3.0.13-0ubuntu3.2" || f.AdvisoryID != "USN-6937-1" ||
		f.AdvisoryURL != "https://ubuntu.com/security/notices/USN-6937-1" || f.Source != "oval" || f.Severity != "low" || len(f.CVEIDs) != 4 {
		t.Fatalf("got %+v", f)
	}

	// Linux Mint is matched against its Ubuntu base.
	q.Product = "linuxmint"
	if got := idx.LookupPackages(q); len(got) != 1 {
		t.Fatalf("linuxmint: got %+v", got)
	}
	// Another release's hosts see nothing from noble's file.
	q.Product, q.Extra = "ubuntu", map[string]string{"codename": "jammy"}
	if got := idx.LookupPackages(q); got != nil {
		t.Fatalf("jammy: got %+v", got)
	}
}

// USN-6816-1 fixes the generic flavour in 6.8.0-35.35. Canonical's own
// variable compares the ABI alone ("6.8.0-35"), which sorts before that
// — ubuntuKernelVersion adds `uname -v`'s upload number so the fixed
// kernel itself isn't flagged.
func TestOVALUbuntuRunningKernel(t *testing.T) {
	idx := loadOVALFixture(t, "oval_ubuntu_noble.xml")
	lookup := func(release, unameV string) []Finding {
		return idx.LookupPackages(PackageQuery{Product: "ubuntu", Version: "24.04", Packages: map[string]string{"bash": "5.2.21-2ubuntu4"},
			Extra: map[string]string{"codename": "noble", "kernelRelease": release, "kernelVersion": unameV}})
	}
	got := lookup("6.8.0-31-generic", "#31-Ubuntu SMP PREEMPT_DYNAMIC Sat Apr 20 00:40:06 UTC 2024")
	if len(got) != 1 || got[0].MatchedName != "kernel linux (6.8.0-31-generic)" || got[0].InstalledVersion != "6.8.0-31.31" || got[0].FixedVersion != "6.8.0-35.35" {
		t.Fatalf("6.8.0-31: got %+v", got)
	}
	if got := lookup("6.8.0-35-generic", "#35-Ubuntu SMP PREEMPT_DYNAMIC Mon May 20 15:51:52 UTC 2024"); len(got) != 0 {
		t.Fatalf("6.8.0-35.35 is the fix itself: got %+v", got)
	}
	// Another flavour's pattern doesn't match a generic kernel, and vice versa.
	if got := lookup("6.8.0-1004-ibm", "#4-Ubuntu SMP"); len(got) != 1 || got[0].MatchedName != "kernel linux-ibm (6.8.0-1004-ibm)" {
		t.Fatalf("ibm: got %+v", got)
	}
}

func TestUbuntuKernelVersion(t *testing.T) {
	for _, tc := range []struct{ release, unameV, want string }{
		{"6.8.0-35-generic", "#35-Ubuntu SMP PREEMPT_DYNAMIC", "6.8.0-35.35"},
		{"6.5.0-35-generic", "#35~22.04.1-Ubuntu SMP", "6.5.0-35.35~22.04.1"}, // HWE
		{"6.8.0-35-generic", "#1 SMP Debian", "6.8.0-35"},                     // not Ubuntu's shape: ABI only
	} {
		if got, ok := ubuntuKernelVersion(tc.release, tc.unameV); !ok || got != tc.want {
			t.Errorf("ubuntuKernelVersion(%q, %q) = %q, %v, want %q", tc.release, tc.unameV, got, ok, tc.want)
		}
	}
	if _, ok := ubuntuKernelVersion("6.12.107+deb13-amd64", ""); ok {
		t.Error("a Debian kernel release isn't Ubuntu's shape")
	}
}

func TestOVALRHELPackagesAndRocky(t *testing.T) {
	idx := loadOVALFixture(t, "oval_rhel9.xml")
	pkgs := map[string]string{"openssl-libs": "1:3.0.7-24.el9", "openssl": "1:3.0.7-28.el9_4"}
	for _, product := range []string{"rhel", "rocky-linux"} {
		got := idx.LookupPackages(PackageQuery{Product: product, Version: "9.3", Packages: pkgs, Extra: map[string]string{}})
		if len(got) != 1 || got[0].MatchedName != "openssl-libs" || got[0].FixedVersion != "1:3.0.7-28.el9_4" ||
			got[0].AdvisoryID != "RHSA-2024:6783" || got[0].Severity != "moderate" {
			t.Fatalf("%s: got %+v", product, got)
		}
	}
	if got := idx.LookupPackages(PackageQuery{Product: "rhel", Version: "8.10", Packages: pkgs}); got != nil {
		t.Fatalf("RHEL 8 against the RHEL 9 file: got %+v", got)
	}
}

// RHEL 9 ships nodejs 16 non-modular and 18/20 as AppStream modules, each
// fixed separately: a package is matched only against its own stream's
// fixes — otherwise nodejs 16 would read as missing stream 18's fix.
func TestOVALRHELModuleStreams(t *testing.T) {
	idx := loadOVALFixture(t, "oval_rhel9.xml")
	lookup := func(ver, module string) []Finding {
		q := PackageQuery{Product: "rhel", Version: "9.2", Packages: map[string]string{"nodejs": ver}}
		if module != "" {
			q.Modules = map[string]string{"nodejs": module}
		}
		return idx.LookupPackages(q)
	}
	if got := lookup("1:16.20.2-1.el9", ""); len(got) != 0 {
		t.Fatalf("non-modular nodejs 16 past its own fix: got %+v", got)
	}
	if got := lookup("1:16.14.0-1.el9", ""); len(got) != 1 || got[0].AdvisoryID != "RHSA-2022:6595" {
		t.Fatalf("non-modular nodejs 16 behind: got %+v", got)
	}
	if got := lookup("1:18.16.1-1.module+el9.2.0.z+19424+78951f07", "nodejs:18"); len(got) != 1 || got[0].AdvisoryID != "RHSA-2023:5363" {
		t.Fatalf("nodejs:18 behind: got %+v", got)
	}
	if got := lookup("1:20.5.1-1.module+el9.2.0+19420+9c9ac521", "nodejs:20"); len(got) != 0 {
		t.Fatalf("nodejs:20 has no fix in this fixture: got %+v", got)
	}
}

// Oracle publishes x86_64 and aarch64 branches, and separate FIPS
// rebuilds (epoch 10, "_fips" release) next to the ordinary packages.
func TestOVALOracleArchAndFIPS(t *testing.T) {
	idx := loadOVALFixture(t, "oval_oracle9.xml")
	lookup := func(ver string) []Finding {
		return idx.LookupPackages(PackageQuery{Product: "oracle-linux", Version: "9.8",
			Packages: map[string]string{"openssl": ver}, Extra: map[string]string{"arch": "x86_64"}})
	}
	got := lookup("1:3.5.1-7.0.1.el9_7")
	if len(got) != 1 || got[0].AdvisoryID != "ELSA-2026-67165-0" || !slices.Equal(got[0].Advisories, []string{"ELSA-2026-67165-0"}) {
		t.Fatalf("ordinary openssl: got %+v, want only the ordinary advisory, once (not per arch)", got)
	}
	got = lookup("10:3.5.1-4.0.2.el9_7_fips")
	if len(got) != 1 || got[0].AdvisoryID != "ELSA-2026-50075" || got[0].FixedVersion != "10:3.5.1-7.0.1.el9_7_fips" {
		t.Fatalf("FIPS openssl: got %+v, want only the FIPS advisory", got)
	}
}

func TestOVALAlmaFromCriterion(t *testing.T) {
	idx := loadOVALFixture(t, "oval_alma9.xml")
	got := idx.LookupPackages(PackageQuery{Product: "almalinux", Version: "9.4", Packages: map[string]string{"openssl": "1:3.0.7-27.el9"}})
	if len(got) != 1 || got[0].AdvisoryID != "ALSA-2024:6783" || !strings.HasPrefix(got[0].AdvisoryURL, "https://errata.almalinux.org/") {
		t.Fatalf("got %+v, want the ALSA (not the RHSA it rebuilds)", got)
	}
}

func TestOVALRejectsNonOVAL(t *testing.T) {
	if _, err := LoadOVAL("testdata/sample.xml"); err == nil {
		t.Fatal("expected an error for a BDU export")
	}
	if _, err := LoadOVAL(t.TempDir()); err == nil {
		t.Fatal("expected an error for a directory with no OVAL files")
	}
}

// The vendors publish .xml.bz2; it's read as-is.
func TestOVALReadsBzip2(t *testing.T) {
	// No bzip2 writer in the standard library: this fixture was made with
	// bzip2(1) from oval_alma9.xml.
	idx, err := LoadOVAL("testdata/oval_alma9.xml.bz2")
	if err != nil || idx.oval["almalinux:9"] == nil {
		t.Fatalf("got %v, %v", idx, err)
	}
}

func TestOVALCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "oval")
	if err := os.Mkdir(src, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"oval_ubuntu_noble.xml", "oval_oracle9.xml"} {
		raw, _ := os.ReadFile(filepath.Join("testdata", n))
		if err := os.WriteFile(filepath.Join(src, n), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cacheDir := filepath.Join(dir, "cache")
	var warnings []string
	warn := func(s string) { warnings = append(warnings, s) }

	first, err := LoadOVALCached(src, cacheDir, warn)
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(cacheDir)
	if len(entries) != 2 {
		t.Fatalf("got %d cache entries, want one per OVAL file", len(entries))
	}
	second, err := LoadOVALCached(src, cacheDir, warn)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("%v, warnings %v", err, warnings)
	}

	q := PackageQuery{Product: "oracle-linux", Version: "9.8", Packages: map[string]string{"openssl": "10:3.5.1-4.0.2.el9_7_fips"}, Extra: map[string]string{"arch": "x86_64"}}
	k := PackageQuery{Product: "ubuntu", Packages: map[string]string{"libssl3t64": "3.0.13-0ubuntu3.1"},
		Extra: map[string]string{"codename": "noble", "kernelRelease": "6.8.0-31-generic", "kernelVersion": "#31-Ubuntu SMP"}}
	for _, query := range []PackageQuery{q, k} {
		a, b := first.LookupPackages(query), second.LookupPackages(query)
		if len(a) == 0 || len(a) != len(b) {
			t.Fatalf("%s: fresh %+v, cached %+v", query.Product, a, b)
		}
		for i := range a {
			if a[i].AdvisoryID != b[i].AdvisoryID || a[i].FixedVersion != b[i].FixedVersion || !slices.Equal(a[i].CVEIDs, b[i].CVEIDs) {
				t.Fatalf("%s: fresh %+v, cached %+v", query.Product, a[i], b[i])
			}
		}
	}
}

// oval_astra17.xml, oval_astra18.xml and oval_redos80.xml are single real
// definitions cut from Astra's own 1.7 and 1.8 OVAL files and RED
// OS's 8.0 redos.xml: one class="vulnerability" definition per CVE,
// holding the fixed package versions.
func TestOVALAstraAndRedOS(t *testing.T) {
	idx := loadOVALFixture(t, "oval_astra17.xml", "oval_astra18.xml", "oval_redos80.xml")
	for _, key := range []string{"astra-linux:1.7", "astra-linux:1.8", "redos:8.0"} {
		if idx.oval[key] == nil {
			t.Fatalf("no release %s loaded; have %v", key, slices.Sorted(maps.Keys(idx.oval)))
		}
	}

	// Astra 1.8: dpkg versions, the vendor's own bulletin as the advisory.
	got := idx.LookupPackages(PackageQuery{Product: "astra-linux", Version: "1.8.1",
		Packages: map[string]string{"libssl3": "3.2.0-2-astra4", "openssl": "3.2.0-2-astra5+ci1"}})
	if len(got) != 1 || got[0].MatchedName != "libssl3" || got[0].FixedVersion != "0:3.2.0-2-astra5+ci1" ||
		got[0].AdvisoryID != "2024-0905SE18MD" || got[0].AdvisoryURL != "https://wiki.astralinux.ru/astra-linux-se18-bulletin-2024-0905SE18MD" ||
		!slices.Equal(got[0].CVEIDs, []string{"CVE-2024-4741"}) {
		t.Fatalf("astra 1.8: got %+v", got)
	}

	// Astra 1.7's definitions cite no bulletin: BDU is the advisory.
	got = idx.LookupPackages(PackageQuery{Product: "astra-linux", Version: "1.7.9",
		Packages: map[string]string{"libc6": "2.28-10+deb10u1+ci202206011200+astra3"}})
	if len(got) != 1 || got[0].AdvisoryID != "BDU:2020-04683" || got[0].AdvisoryURL != "https://bdu.fstec.ru/vul/2020-04683" {
		t.Fatalf("astra 1.7: got %+v", got)
	}

	// RED OS 8.0: rpm versions, its ROS bulletin, its severity.
	got = idx.LookupPackages(PackageQuery{Product: "redos", Version: "8.0.3",
		Packages: map[string]string{"openssl-libs": "1:3.5.4-2.red80"}})
	if len(got) != 1 || got[0].AdvisoryID != "ROS-20260420-80-0001" || got[0].Severity != "medium" || got[0].FixedVersion != "1:3.5.5-1.red80" {
		t.Fatalf("redos 8.0: got %+v", got)
	}
	if got := idx.LookupPackages(PackageQuery{Product: "redos", Version: "7.3.1", Packages: map[string]string{"openssl-libs": "1:1.1.1g-15.el7"}}); got != nil {
		t.Fatalf("redos 7.3 against the 8.0 file: got %+v", got)
	}
}

// Everyone else's class="vulnerability" definitions aren't read: only the
// two vendors above use it for fixed versions.
func TestOVALVulnerabilityClassOnlyForAstraAndRedOS(t *testing.T) {
	raw, err := os.ReadFile("testdata/oval_rhel9.xml")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rhel.xml")
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(string(raw), `class="patch"`, `class="vulnerability"`)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOVAL(path); err == nil {
		t.Fatal("expected no usable definitions")
	}
}
