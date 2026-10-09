// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
)

// atlassianSource is Finding.Source for Atlassian's own vulnerability
// transparency data.
const atlassianSource = "atlassian"

// atlassianProducts maps an enodia product to the Atlassian product names
// its versions are listed under in
// https://api.atlassian.com/vuln-transparency/v1/products. The probe reads
// the Application Links manifest, which doesn't say Server or Data Center,
// so both are read and a version is affected when either lists it.
// Jira's own version is Jira Software's (and Jira Core's); Jira Service
// Management numbers its releases separately and isn't mapped.
var atlassianProducts = map[string][]string{
	"bamboo":     {"Bamboo Data Center", "Bamboo Server"},
	"bitbucket":  {"Bitbucket Data Center", "Bitbucket Server"},
	"confluence": {"Confluence Data Center", "Confluence Server"},
	"jira":       {"Jira Software Data Center", "Jira Software Server", "Jira Core Data Center", "Jira Core Server"},
}

type atlassianExport struct {
	Products map[string]struct {
		// version -> [{CVE: "AFFECTED"|"FIXED"}, ...]
		Versions map[string][]map[string]string `json:"versions"`
	} `json:"products"`
	CVEMetadata map[string]struct {
		Summary     string  `json:"cve_summary"`
		Severity    float64 `json:"cve_severity"`
		TrackingURL string  `json:"atl_tracking_url"`
	} `json:"cve_metadata"`
}

// LoadAtlassian reads Atlassian's vulnerability transparency export
// (cve.atlassian.path) — every listed release of each product, with the
// CVEs it is affected by and the ones fixed in it. See
// docs/DECISIONS.md D69. Each affected span within a branch, up to the
// release that fixes it, becomes one finding; the Index also records every CVE and every release
// the export knows, so Lookup can let Atlassian's verdict replace BDU's
// and NVD's for a release Atlassian has listed.
func LoadAtlassian(path string) (*Index, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var exp atlassianExport
	if err := json.Unmarshal(raw, &exp); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(exp.Products) == 0 {
		return nil, fmt.Errorf("%s: no products — is this Atlassian's vuln-transparency /v1/products export?", path)
	}

	idx := &Index{
		byProduct:    map[string][]Finding{},
		vendorCVEs:   map[string]map[string]bool{},
		vendorCovers: map[string]func([]int) bool{},
	}
	// Every CVE the export lists for any product: Atlassian lists each
	// release with every CVE that affects it, so a CVE it tracks but never
	// lists against, say, Jira doesn't affect Jira. Found live: BDU files
	// three Confluence CVEs (CVE-2024-21672..21674) under "Jira Data Center".
	tracked := map[string]bool{}
	for _, p := range exp.Products {
		for _, entries := range p.Versions {
			for _, e := range entries {
				for id := range e {
					tracked[id] = true
				}
			}
		}
	}

	for product, names := range atlassianProducts {
		type release struct {
			version string
			parts   []int
		}
		var releases []release
		seen := map[string]bool{}
		status := map[string]map[string]string{} // CVE -> version -> status
		for _, name := range names {
			for v, entries := range exp.Products[name].Versions {
				parts, ok := cleanVersionParts(v)
				if !ok { // "10.0.0-rc3", "8.14.0-eap01": never a production release
					continue
				}
				if !seen[v] {
					seen[v] = true
					releases = append(releases, release{v, parts})
				}
				for _, e := range entries {
					for id, st := range e {
						if status[id] == nil {
							status[id] = map[string]string{}
						}
						// AFFECTED in either edition wins.
						if status[id][v] != "AFFECTED" {
							status[id][v] = st
						}
					}
				}
			}
		}
		if len(releases) == 0 {
			continue
		}
		slices.SortFunc(releases, func(a, b release) int { return comparePartsSlices(a.parts, b.parts) })
		known := map[string]bool{}
		for _, r := range releases {
			known[joinParts(r.parts)] = true
		}
		idx.vendorCovers[product] = func(parts []int) bool { return known[joinParts(parts)] }
		idx.vendorCVEs[product] = tracked

		ids := make([]string, 0, len(status))
		for id := range status {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		for _, id := range ids {
			meta := exp.CVEMetadata[id]
			base := Finding{
				Source: atlassianSource, AdvisoryID: id, CVEIDs: []string{id},
				Title: meta.Summary, MatchedName: strings.Join(names, ", "), AdvisoryURL: meta.TrackingURL,
			}
			if meta.Severity > 0 {
				base.CVSS = CVSS{Version: "3.1", Score: meta.Severity, Severity: cvssV3Severity(meta.Severity)}
			}
			// The export is sparse: a CVE is listed at the first affected
			// release of a branch and at its fix, rarely at every release
			// between ("8.5.0 AFFECTED", "8.5.10 FIXED"), and a branch it
			// never lists isn't affected. So, within one major.minor
			// branch, a range runs from an affected release up to the
			// next release listed as fixing it; a branch with no fix after
			// an affected release is flagged to its end.
			var start *release
			flush := func(next *release) {
				if start == nil {
					return
				}
				f := base
				if next != nil && atlassianBranch(next.parts) == atlassianBranch(start.parts) {
					f.rng = versionRange{Lo: start.parts, LoInclusive: true, Hi: next.parts}
					f.RangeText = start.version + " before " + next.version
					f.FixedVersion = next.version
				} else {
					br := atlassianBranch(start.parts)
					f.rng = versionRange{Lo: start.parts, LoInclusive: true, Hi: []int{br[0], br[1] + 1}}
					f.RangeText = fmt.Sprintf("%s and later %d.%d", start.version, br[0], br[1])
					f.FixStatus = fmt.Sprintf("no fix listed for %d.%d", br[0], br[1])
				}
				idx.byProduct[product] = append(idx.byProduct[product], f)
				start = nil
			}
			for i := range releases {
				r := &releases[i]
				if start != nil && atlassianBranch(r.parts) != atlassianBranch(start.parts) {
					flush(nil)
				}
				switch status[id][r.version] {
				case "AFFECTED":
					if start == nil {
						start = r
					}
				case "FIXED":
					flush(r)
				}
			}
			flush(nil)
		}
	}
	return idx, nil
}

// atlassianBranch is a release's major.minor ("10.3").
func atlassianBranch(parts []int) [2]int {
	var b [2]int
	copy(b[:], parts)
	return b
}
