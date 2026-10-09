// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
)

// nginxSource is Finding.Source for nginx's own security advisories.
const nginxSource = "nginx"

var (
	nginxItemPattern = regexp.MustCompile(`(?s)<li><p>(.*?)</p></li>`)
	nginxCVEPattern  = regexp.MustCompile(`CVE-\d{4}-\d+`)
	nginxVulnPattern = regexp.MustCompile(`<br>Vulnerable:\s*([^<]*)`)
	nginxFixPattern  = regexp.MustCompile(`<br>Not vulnerable:\s*([^<]*)`)
	nginxSevPattern  = regexp.MustCompile(`<br>Severity:\s*(?:<b>)?([a-z]+)`)
	nginxLinkPattern = regexp.MustCompile(`<a href="(https://[^"]+)">Advisory</a>`)
)

// LoadNginx reads nginx's own security advisories
// (cve.nginx.path): https://nginx.org/en/security_advisories.html saved
// as is. Each advisory gives the vulnerable versions ("0.9.6-1.31.2") and,
// per branch, the first release that isn't ("1.31.3+, 1.30.4+"). See
// docs/DECISIONS.md D71.
func LoadNginx(path string) (*Index, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	idx := &Index{byProduct: map[string][]Finding{}, vendorCVEs: map[string]map[string]bool{"nginx": {}}}
	for _, item := range nginxItemPattern.FindAllStringSubmatch(string(raw), -1) {
		body := item[1]
		ids := nginxCVEPattern.FindAllString(body, -1)
		vuln := nginxVulnPattern.FindStringSubmatch(body)
		if len(ids) == 0 || vuln == nil {
			continue
		}
		id := ids[0]
		title, _, _ := strings.Cut(body, "<br>")
		base := Finding{
			Source: nginxSource, AdvisoryID: id, CVEIDs: []string{id},
			Title: pgText(title), MatchedName: "nginx",
			AdvisoryURL: "https://nginx.org/en/security_advisories.html",
		}
		if m := nginxLinkPattern.FindStringSubmatch(body); m != nil {
			base.AdvisoryURL = m[1]
		}
		if m := nginxSevPattern.FindStringSubmatch(body); m != nil {
			base.Severity = m[1]
		}
		var fixes [][]int
		if m := nginxFixPattern.FindStringSubmatch(body); m != nil {
			for _, f := range strings.Split(m[1], ",") {
				if parts, ok := cleanVersionParts(strings.TrimSuffix(strings.TrimSpace(f), "+")); ok {
					fixes = append(fixes, parts)
				}
			}
		}
		ranges, ok := nginxVulnerable(vuln[1], fixes)
		// nginx/Windows-only advisories, and the 2009 "all"/"none" one,
		// say nothing about a Unix build's version.
		if !ok {
			continue
		}
		idx.vendorCVEs["nginx"][id] = true
		for _, r := range ranges {
			f := base
			f.rng = r
			f.RangeText = r.String()
			if r.Hi != nil && !r.HiInclusive && slices.ContainsFunc(fixes, func(p []int) bool { return comparePartsSlices(p, r.Hi) == 0 }) {
				f.FixedVersion = joinParts(r.Hi)
			}
			idx.byProduct["nginx"] = append(idx.byProduct["nginx"], f)
		}
	}
	if len(idx.vendorCVEs["nginx"]) == 0 {
		return nil, fmt.Errorf("%s: no advisories — is this https://nginx.org/en/security_advisories.html?", path)
	}
	return idx, nil
}

// nginxVulnerable turns an advisory's "Vulnerable:" text ("1.25.0-1.25.5,
// 1.26.0") and its "Not vulnerable:" releases into ranges. A fixed release
// covers the rest of its own branch ("1.30.4+" is 1.30.4 and later 1.30);
// the newest one covers everything after it too. Whatever of the
// vulnerable span those don't cover stays vulnerable — older branches
// that never got the fix included.
func nginxVulnerable(text string, fixes [][]int) ([]versionRange, bool) {
	var newest []int
	for _, f := range fixes {
		if newest == nil || comparePartsSlices(f, newest) > 0 {
			newest = f
		}
	}
	var out []versionRange
	for _, span := range strings.Split(text, ",") {
		lo, hi, isRange := strings.Cut(strings.TrimSpace(span), "-")
		if !isRange {
			hi = lo
		}
		loP, ok1 := cleanVersionParts(lo)
		hiP, ok2 := cleanVersionParts(hi)
		if !ok1 || !ok2 {
			return nil, false
		}
		pieces := []versionRange{{Lo: loP, LoInclusive: true, Hi: hiP, HiInclusive: true}}
		for _, f := range fixes {
			cut := versionRange{Lo: f, LoInclusive: true}
			if comparePartsSlices(f, newest) != 0 && len(f) >= 2 {
				cut.Hi = []int{f[0], f[1] + 1}
			}
			pieces = subtractRange(pieces, cut)
		}
		out = append(out, pieces...)
	}
	return out, len(out) > 0
}

// subtractRange removes cut (inclusive Lo, exclusive Hi or open) from each
// of pieces.
func subtractRange(pieces []versionRange, cut versionRange) []versionRange {
	var out []versionRange
	for _, p := range pieces {
		// The part below cut.Lo.
		if comparePartsSlices(p.Lo, cut.Lo) < 0 {
			below := p
			if comparePartsSlices(p.Hi, cut.Lo) >= 0 {
				below.Hi, below.HiInclusive = cut.Lo, false
			}
			out = append(out, below)
		}
		// The part from cut.Hi on.
		if cut.Hi != nil {
			cmp := comparePartsSlices(p.Hi, cut.Hi)
			if cmp > 0 || (cmp == 0 && p.HiInclusive) {
				above := p
				if comparePartsSlices(p.Lo, cut.Hi) < 0 {
					above.Lo, above.LoInclusive = cut.Hi, true
				}
				out = append(out, above)
			}
		}
	}
	return out
}
