// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"cmp"
	"slices"
	"strconv"
	"strings"

	"github.com/EpicMorg/enodia/internal/cve"
)

// cveGroup is every Finding about one CVE, as a person reads it: BDU and
// NVD each report the same CVE on their own, and NVD repeats it once per
// matching CPE (confluence_server and confluence_data_center are two
// findings for one CVE-2023-22515). Grouping is presentation only — the
// JSON export keeps every per-source Finding as the fact it is (D7).
type cveGroup struct {
	key     string   // the CVE ID, or a BDU AdvisoryID for a finding that cites none
	cveIDs  []string // in first-seen order
	bduIDs  []string
	title   string
	rating  cve.CVSS
	rawText string // a source's own severity text, when no rating parsed at all
	tags    []string
}

// cveGroupKey is what findings are merged on. A BDU finding citing
// several CVEs is filed under its first; the rest still show on its line.
func cveGroupKey(f cve.Finding) string {
	if len(f.CVEIDs) > 0 {
		return f.CVEIDs[0]
	}
	return f.AdvisoryID
}

// distinctCVECount is how many cveGroups findings make — the CVES column's
// number, so it counts CVEs rather than per-source, per-CPE findings.
func distinctCVECount(findings []cve.Finding) int {
	seen := make(map[string]bool, len(findings))
	for _, f := range findings {
		seen[cveGroupKey(f)] = true
	}
	return len(seen)
}

// groupCVEs merges findings per CVE and sorts the result most severe
// first. Within a group the title comes from BDU when it has one — it's
// the Russian text, which is what this report's own operators read — and
// NVD's English description otherwise. The rating comes from NVD when it
// has one (NVD is the CVSS scoring authority BDU itself cites), BDU's
// otherwise.
func groupCVEs(findings []cve.Finding) []cveGroup {
	byKey := map[string]*cveGroup{}
	var order []string
	for _, f := range findings {
		k := cveGroupKey(f)
		g, ok := byKey[k]
		if !ok {
			g = &cveGroup{key: k}
			byKey[k] = g
			order = append(order, k)
		}
		for _, id := range f.CVEIDs {
			if !slices.Contains(g.cveIDs, id) {
				g.cveIDs = append(g.cveIDs, id)
			}
		}
		if f.Source == "bdu" && !slices.Contains(g.bduIDs, f.AdvisoryID) {
			g.bduIDs = append(g.bduIDs, f.AdvisoryID)
		}
		if f.Title != "" && (g.title == "" || f.Source == "bdu") {
			g.title = f.Title
		}
		if f.CVSS.Severity != "" && (g.rating.Severity == "" || f.Source == "nvd") {
			g.rating = f.CVSS
		}
		if g.rawText == "" {
			g.rawText = f.Severity
		}
		for _, tag := range []string{f.Source, f.Edition} {
			if tag != "" && !slices.Contains(g.tags, tag) {
				g.tags = append(g.tags, tag)
			}
		}
	}

	out := make([]cveGroup, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	slices.SortStableFunc(out, func(a, b cveGroup) int {
		if c := cmp.Compare(b.rating.Score, a.rating.Score); c != 0 {
			return c
		}
		if c := cmp.Compare(severityRank(b.rating.Severity), severityRank(a.rating.Severity)); c != 0 {
			return c
		}
		return compareCVEIDs(b.key, a.key) // newest first
	})
	return out
}

func severityRank(s string) int {
	switch s {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// compareCVEIDs orders "CVE-YYYY-N" by year then number, numerically —
// "CVE-2026-9807" before "CVE-2026-85706" — and anything else as a plain
// string after them.
func compareCVEIDs(a, b string) int {
	ay, an, aok := splitCVEID(a)
	by, bn, bok := splitCVEID(b)
	switch {
	case aok && bok:
		if c := cmp.Compare(ay, by); c != 0 {
			return c
		}
		return cmp.Compare(an, bn)
	case aok != bok:
		if aok {
			return 1
		}
		return -1
	default:
		return strings.Compare(a, b)
	}
}

func splitCVEID(id string) (year, num int, ok bool) {
	rest, found := strings.CutPrefix(id, "CVE-")
	if !found {
		return 0, 0, false
	}
	ys, ns, found := strings.Cut(rest, "-")
	if !found {
		return 0, 0, false
	}
	y, err1 := strconv.Atoi(ys)
	n, err2 := strconv.Atoi(ns)
	return y, n, err1 == nil && err2 == nil
}

// ratingText is a group's short severity: "CRITICAL · CVSS 3.1 9.8" from a
// parsed rating, or the source's own text when none parsed.
func (g cveGroup) ratingText() string {
	r := g.rating
	switch {
	case r.Severity != "" && r.Score > 0:
		return r.Severity + " · CVSS " + r.Version + " " + strconv.FormatFloat(r.Score, 'f', -1, 64)
	case r.Severity != "":
		return r.Severity
	default:
		return g.rawText
	}
}
