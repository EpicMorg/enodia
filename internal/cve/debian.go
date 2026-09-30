// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/EpicMorg/enodia/internal/version"
)

// debianFix is one CVE the Debian Security Tracker records as fixed, in
// one release, for one source package: installed versions older than
// Fixed are affected.
type debianFix struct {
	CVE     string
	Fixed   string
	Urgency string
}

// debianTracker is the Debian Security Tracker's JSON export reduced to
// what package-level matching needs: release codename -> source package
// -> every fixed CVE. Only "resolved" entries with a real fixed version
// are kept — see LoadDebianTracker for why open ones are dropped.
type debianTracker map[string]map[string][]debianFix

// trackerRelease is one release's entry for one CVE in the tracker's
// JSON (https://security-tracker.debian.org/tracker/data/json). Only the
// fields matching needs; description, scope, repositories and nodsa are
// skipped by the decoder.
type trackerRelease struct {
	Status       string `json:"status"`
	FixedVersion string `json:"fixed_version"`
	Urgency      string `json:"urgency"`
}

// LoadDebianTracker parses the Debian Security Tracker's JSON export
// (the operator downloads https://security-tracker.debian.org/tracker/data/json
// themselves, the same offline model as BDU and NVD — see
// docs/DECISIONS.md D42). path may be .json, .json.gz or .json.zip.
//
// Kept: status "resolved" with a fixed_version other than "0" (the
// tracker's "never affected" marker) — the CVEs an `apt upgrade` would
// actually close. Dropped: "open" and "undetermined", CVEs Debian has no
// fix for yet. Measured on a real trixie host: ~2000 of them, 813 in the
// kernel alone, and the same ones on every host of that release — a
// constant nobody can act on, which would bury the handful that can be.
//
// No on-disk cache, unlike BDU and NVD: the whole ~80MB export parses in
// under a second, so a cache would only add a way to go stale.
func LoadDebianTracker(path string) (*Index, error) {
	r, closeFn, err := openNVDSource(path)
	if err != nil {
		return nil, err
	}
	defer closeFn()

	var raw map[string]map[string]struct {
		Releases map[string]trackerRelease `json:"releases"`
	}
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s: no source packages — is this the Debian Security Tracker's JSON export?", path)
	}

	tr := debianTracker{}
	for src, cves := range raw {
		for id, e := range cves {
			for release, r := range e.Releases {
				if r.Status != "resolved" || r.FixedVersion == "" || r.FixedVersion == "0" {
					continue
				}
				if tr[release] == nil {
					tr[release] = map[string][]debianFix{}
				}
				tr[release][src] = append(tr[release][src], debianFix{CVE: id, Fixed: r.FixedVersion, Urgency: r.Urgency})
			}
		}
	}
	return &Index{byProduct: map[string][]Finding{}, debian: tr}, nil
}

// urgencyRank orders the tracker's own urgency words, most urgent last.
// "not yet assigned" (the tracker's default, ~80% of real entries) ranks
// with the empty string: no rating at all, not a low one.
func urgencyRank(u string) int {
	switch u {
	case "unimportant":
		return 1
	case "low":
		return 2
	case "medium":
		return 3
	case "high":
		return 4
	}
	return 0
}

// LookupPackages returns one Finding per installed source package the
// Debian Security Tracker says is behind a security fix, for an
// observation of product with the given packages (source package ->
// version, see probe.Observation.Packages) and Extra. Only product
// "debian" has package data today; every other product gets nil.
//
// Extra["codename"] picks the tracker release. Extra["kernel"], when the
// probe found one, is the running kernel's own Debian version and is used
// for source package "linux" instead of whatever linux-* packages are
// installed: a fixed kernel that is installed but not booted is still the
// vulnerable one — and old linux-headers are routinely left installed
// (confirmed live: 6.12.74-2 headers next to a running 6.12.107-1).
//
// One Finding per package, not per CVE: confirmed live, a trixie host one
// kernel update behind has 1314 fixed-but-not-installed kernel CVEs, and
// the thing to act on is one package upgrade, not 1314 lines. CVEIDs
// carries every CVE; FixedVersion is the newest fix among them — the
// version that closes all of them.
func (idx *Index) LookupPackages(product string, packages, extra map[string]string) []Finding {
	if idx == nil || idx.debian == nil || product != "debian" || len(packages) == 0 {
		return nil
	}
	byPkg := idx.debian[extra["codename"]]
	if byPkg == nil {
		return nil
	}

	installed := packages
	if k := extra["kernel"]; k != "" {
		if _, ok := packages["linux"]; ok || byPkg["linux"] != nil {
			installed = maps.Clone(packages)
			installed["linux"] = k
		}
	}

	var out []Finding
	for _, src := range slices.Sorted(maps.Keys(installed)) {
		have := installed[src]
		var f Finding
		for _, fix := range byPkg[src] {
			if version.CompareDebian(have, fix.Fixed) >= 0 {
				continue
			}
			f.CVEIDs = append(f.CVEIDs, fix.CVE)
			if f.FixedVersion == "" || version.CompareDebian(fix.Fixed, f.FixedVersion) > 0 {
				f.FixedVersion = fix.Fixed
			}
			if urgencyRank(fix.Urgency) > urgencyRank(f.Severity) {
				f.Severity = fix.Urgency
			}
		}
		if len(f.CVEIDs) == 0 {
			continue
		}
		slices.SortFunc(f.CVEIDs, compareCVEID)
		f.CVEIDs = slices.Compact(f.CVEIDs)
		f.Source = "debian"
		f.AdvisoryID = src
		f.MatchedName = src
		f.InstalledVersion = have
		f.RangeText = "< " + f.FixedVersion
		f.Title = fmt.Sprintf("%s %s: %d CVE(s) fixed in %s", src, have, len(f.CVEIDs), f.FixedVersion)
		out = append(out, f)
	}
	return out
}

// compareCVEID orders "CVE-YYYY-N" ids numerically by year, then number.
func compareCVEID(a, b string) int {
	ay, an := splitCVE(a)
	by, bn := splitCVE(b)
	if ay != by {
		return ay - by
	}
	if an != bn {
		return an - bn
	}
	return strings.Compare(a, b)
}

func splitCVE(id string) (year, num int) {
	rest, _ := strings.CutPrefix(id, "CVE-")
	y, n, _ := strings.Cut(rest, "-")
	year, _ = strconv.Atoi(y)
	num, _ = strconv.Atoi(n)
	return year, num
}
