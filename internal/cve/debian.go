// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
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

// lookupDebian is LookupPackages for product "debian": q.Packages are
// source packages, q.Extra["codename"] picks the tracker release.
//
// Source package "linux" is matched against the running kernel only —
// q.Extra["kernel"], the Debian version `uname -v` reports — never against
// whatever linux-* packages are installed: a fixed kernel installed but
// not booted is still the vulnerable one, and old linux-headers are
// routinely left behind (confirmed live: 6.12.74-2 headers next to a
// running 6.12.107-1). No Debian kernel running (a Proxmox VE host runs
// its own, and gets linux-libc-dev from Debian's linux source) means no
// "linux" findings at all, rather than hundreds of kernel CVEs matched
// against a C headers package.
func (idx *Index) lookupDebian(q PackageQuery) []Finding {
	byPkg := idx.debian[q.Extra["codename"]]
	if byPkg == nil {
		return nil
	}
	installed := maps.Clone(q.Packages)
	delete(installed, "linux")
	if k := q.Extra["kernel"]; k != "" {
		installed["linux"] = k
	}

	var out []Finding
	for _, src := range slices.Sorted(maps.Keys(installed)) {
		have := installed[src]
		agg := packageAggregate{cmp: version.CompareDebian, rank: urgencyRank}
		for _, fix := range byPkg[src] {
			if version.CompareDebian(have, fix.Fixed) < 0 {
				agg.add(fix.Fixed, fix.Urgency, nil, fix.CVE)
			}
		}
		if f, ok := agg.finding("debian", src, have); ok {
			f.AdvisoryID = src
			f.AdvisoryURL = "https://security-tracker.debian.org/tracker/source-package/" + url.PathEscape(src)
			out = append(out, f)
		}
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
