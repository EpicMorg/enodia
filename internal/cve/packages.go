// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/EpicMorg/enodia/internal/version"
)

// PackageQuery is what package-level matching reads from one observation.
type PackageQuery struct {
	Product string
	// Version is the observation's own version ("9.4", "24.04.1"); the
	// RHEL family picks its OVAL file by its major number.
	Version string
	// Packages is probe.Observation.Packages: package -> installed
	// version. Source packages for debian (what the Debian Security
	// Tracker is keyed on), binary packages for ubuntu and the RHEL family
	// (what their OVAL tests name).
	Packages map[string]string
	// Modules is probe.Observation.Modules: an RHEL-family package's
	// AppStream module stream ("nodejs:20"), for modular packages only.
	Modules map[string]string
	Extra   map[string]string
}

// LookupPackages returns one Finding per installed package its
// distribution's own security data says is behind a security fix:
// debian against the Debian Security Tracker (D42); ubuntu (and
// linuxmint, against its Ubuntu base), rhel, almalinux, oracle-linux and
// rocky-linux against their vendor's OVAL (D43), as are astra-linux and
// redos (D46); alpine-linux against Alpine's secdb (D44). Every other product, or one whose release has no
// data loaded, gets nil.
//
// One Finding per package, not per CVE: confirmed live, a trixie host one
// kernel update behind has 1314 fixed-but-not-installed kernel CVEs, and
// the thing to act on is one package upgrade, not 1314 lines. CVEIDs
// carries every CVE; FixedVersion is the newest fix among them — the
// version that closes all of them.
func (idx *Index) LookupPackages(q PackageQuery) []Finding {
	if idx == nil || len(q.Packages) == 0 && q.Extra["kernelRelease"] == "" {
		return nil
	}
	switch q.Product {
	case "debian":
		if idx.debian != nil {
			return idx.lookupDebian(q)
		}
	case "ubuntu", "linuxmint", "rhel", "almalinux", "oracle-linux", "rocky-linux", "astra-linux", "redos":
		if idx.oval != nil {
			return idx.lookupOVAL(q)
		}
	case "alpine-linux":
		if idx.alpine != nil {
			return idx.lookupAlpine(q)
		}
	}
	return nil
}

// packageAggregate folds every missing fix for one package into one
// Finding.
type packageAggregate struct {
	cmp        func(a, b string) int
	rank       func(severity string) int
	cves       []string
	advisories []string
	fixed      string
	severity   string
	newest     *ovalAdvisory // the advisory carrying the newest fix
}

func (a *packageAggregate) add(fixed, severity string, adv *ovalAdvisory, cves ...string) {
	a.cves = append(a.cves, cves...)
	if adv != nil {
		a.cves = append(a.cves, adv.CVEs...)
		if adv.ID != "" && !slices.Contains(a.advisories, adv.ID) {
			a.advisories = append(a.advisories, adv.ID)
		}
	}
	if a.fixed == "" || a.cmp(fixed, a.fixed) > 0 {
		a.fixed = fixed
		a.newest = adv
	}
	if a.rank(severity) > a.rank(a.severity) {
		a.severity = severity
	}
}

func (a *packageAggregate) finding(source, pkg, installed string) (Finding, bool) {
	if len(a.cves) == 0 {
		return Finding{}, false
	}
	cves := slices.Clone(a.cves)
	slices.SortFunc(cves, compareCVEID)
	cves = slices.Compact(cves)
	f := Finding{
		Source:           source,
		CVEIDs:           cves,
		MatchedName:      pkg,
		InstalledVersion: installed,
		FixedVersion:     a.fixed,
		RangeText:        "< " + a.fixed,
		Severity:         a.severity,
		Title:            fmt.Sprintf("%s %s: %d CVE(s) fixed in %s", pkg, installed, len(cves), a.fixed),
	}
	if len(a.advisories) > 0 {
		f.Advisories = slices.Clone(a.advisories)
		slices.Sort(f.Advisories)
	}
	if a.newest != nil {
		f.AdvisoryID, f.AdvisoryURL = a.newest.ID, a.newest.URL
	}
	return f, true
}

// vendorSeverityRank orders the severity words OVAL vendors use, most
// severe last: Red Hat and its rebuilds (Critical, Important, Moderate,
// Low), Oracle the same in capitals, Canonical (Critical, High, Medium,
// Low, Negligible, None).
func vendorSeverityRank(s string) int {
	switch strings.ToLower(s) {
	case "negligible", "none":
		return 1
	case "low":
		return 2
	case "moderate", "medium":
		return 3
	case "important", "high":
		return 4
	case "critical":
		return 5
	}
	return 0
}

// reUbuntuUploadNumber reads the upload number off Ubuntu's `uname -v`:
// "#35-Ubuntu SMP ..." or, for an HWE kernel, "#36~22.04.1-Ubuntu SMP ...".
var reUbuntuUploadNumber = regexp.MustCompile(`^#(\d+(?:~[\d.]+)?)-Ubuntu\b`)

// reUbuntuKernelABI is Canonical's own capture of the ABI from `uname -r`
// ("6.8.0-35-generic" -> "6.8.0-35"), as its OVAL's local_variable does.
var reUbuntuKernelABI = regexp.MustCompile(`^([\d.]+-\d+)[-\w]+$`)

// ubuntuKernelVersion is the running kernel's full package version:
// `uname -r`'s ABI plus `uname -v`'s upload number ("6.8.0-35" + "35" ->
// "6.8.0-35.35"). Canonical's OVAL compares the ABI alone ("0:6.8.0-35"),
// which sorts before its own fixed version "6.8.0-35.35" — so the very
// kernel that carries a fix would read as still missing it. Falls back to
// the ABI when `uname -v` doesn't have the expected shape.
func ubuntuKernelVersion(release, unameV string) (string, bool) {
	m := reUbuntuKernelABI.FindStringSubmatch(release)
	if m == nil {
		return "", false
	}
	if u := reUbuntuUploadNumber.FindStringSubmatch(strings.TrimSpace(unameV)); u != nil {
		return m[1] + "." + u[1], true
	}
	return m[1], true
}

// ovalVariant is which of Oracle's rebuilt variants an installed version
// is, by the marker Oracle puts in its release: "10:3.5.1-7.0.1.el9_7_fips",
// "3.0.7-27.0.1.ksplice1.el9". Empty for an ordinary package.
func ovalVariant(installed string) string {
	switch {
	case strings.Contains(installed, "_fips"):
		return "fips"
	case strings.Contains(installed, "ksplice"):
		return "ksplice"
	}
	return ""
}

// lookupOVAL is LookupPackages for the OVAL-backed products.
func (idx *Index) lookupOVAL(q PackageQuery) []Finding {
	product, release, cmp := q.Product, q.Extra["codename"], version.CompareDebian
	switch q.Product {
	case "ubuntu":
	case "linuxmint":
		// Mint's base packages are Ubuntu's own, from Ubuntu's archive;
		// the probe reports its Ubuntu base in Extra["codename"]
		// (os-release UBUNTU_CODENAME).
		product = "ubuntu"
	case "astra-linux", "redos":
		// Both vendors' OVAL files are per minor release ("Astra Linux 1.8",
		// "RED OS 7.3"), and so are their probes' versions ("1.8.6", "7.3.1").
		release = ""
		if parts := strings.SplitN(q.Version, ".", 3); len(parts) >= 2 {
			release = parts[0] + "." + parts[1]
		}
		if q.Product == "redos" {
			cmp = version.CompareRPM
		}
	case "rocky-linux":
		// Rocky rebuilds RHEL's packages with the same version-release, and
		// its own OVAL is unusable (see loadOVALFile). Measured on a real
		// Rocky 9.3 host against `dnf updateinfo list --security`: RHEL's
		// OVAL flags all 52 packages dnf does.
		product = "rhel"
		release, _, _ = strings.Cut(q.Version, ".")
		cmp = version.CompareRPM
	default:
		release, _, _ = strings.Cut(q.Version, ".")
		cmp = version.CompareRPM
	}
	rel := idx.oval[ovalReleaseKey(product, release)]
	if rel == nil {
		return nil
	}

	var out []Finding
	for _, pkg := range slices.Sorted(maps.Keys(q.Packages)) {
		have := q.Packages[pkg]
		agg := packageAggregate{cmp: cmp, rank: vendorSeverityRank}
		for _, fix := range rel.fixes[pkg] {
			if fix.Module != q.Modules[pkg] {
				continue // a different module stream's fix, or a modular fix for a non-modular package (or the reverse)
			}
			if fix.Arch != "" && q.Extra["arch"] != "" && fix.Arch != q.Extra["arch"] {
				continue
			}
			if fix.Variant != ovalVariant(have) {
				continue // Oracle's Ksplice/FIPS rebuilds and the ordinary packages are fixed separately
			}
			if cmp(have, fix.Fixed) < 0 {
				agg.add(fix.Fixed, fix.adv.Severity, fix.adv)
			}
		}
		if f, ok := agg.finding("oval", pkg, have); ok {
			out = append(out, f)
		}
	}

	if kr := q.Extra["kernelRelease"]; kr != "" && len(rel.kernels) > 0 {
		if have, ok := ubuntuKernelVersion(kr, q.Extra["kernelVersion"]); ok {
			byFlavour := map[string]*packageAggregate{}
			for _, k := range rel.kernels {
				if !k.Pattern.MatchString(kr) || cmp(have, k.Fixed) >= 0 {
					continue
				}
				if byFlavour[k.Flavour] == nil {
					byFlavour[k.Flavour] = &packageAggregate{cmp: cmp, rank: vendorSeverityRank}
				}
				byFlavour[k.Flavour].add(k.Fixed, k.adv.Severity, k.adv)
			}
			for _, flavour := range slices.Sorted(maps.Keys(byFlavour)) {
				if f, ok := byFlavour[flavour].finding("oval", "kernel "+flavour+" ("+kr+")", have); ok {
					out = append(out, f)
				}
			}
		}
	}
	return out
}
