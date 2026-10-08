// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// mariadbSource is Finding.Source for MariaDB's own fixed-versions table.
const mariadbSource = "mariadb"

// mariadbRowPattern is one row of MariaDB's "Security Vulnerabilities
// (CVE) Fixed in MariaDB Community Server" table, as its Markdown source
// (https://mariadb.com/docs/server/security/cve/community-server.md)
// carries it: CVE link | published | CVSS 3.1 base score | releases.
var mariadbRowPattern = regexp.MustCompile(`^\|\s*\[(CVE-\d{4}-\d+)\]\([^)]*\)\s*\|[^|]*\|\s*([^|]*?)\s*\|(.*)\|\s*$`)

// mariadbFixPattern is one release in a row's last cell:
// "[11.4.10](/docs/release-notes/...) (2026-02-04)". The date is missing
// on some real rows, and rows from 2012 name a whole series ("[5.5](...)")
// rather than a release — those carry no bound to compare against and are
// skipped.
var mariadbFixPattern = regexp.MustCompile(`\[(\d+\.\d+\.\d+)\]\([^)]*\)(?:\s*\((\d{4}-\d\d-\d\d)\))?`)

type mariadbFix struct {
	version string
	parts   []int
	date    string // "" when the table gives none
}

type mariadbCVE struct {
	id    string
	score float64 // 0 when the table says N/A
	fixes []mariadbFix
}

// LoadMariaDB reads MariaDB's own fixed-versions table (cve.mariadb.path)
// into findings for product "mariadb", one per CVE and affected series —
// see docs/DECISIONS.md D50 for the rules. The Index also records every
// CVE the table knows, which is what lets Lookup drop BDU/NVD findings
// the vendor's own data says don't apply.
func LoadMariaDB(path string) (*Index, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rows []mariadbCVE
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		m := mariadbRowPattern.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		row := mariadbCVE{id: m[1]}
		if s, err := strconv.ParseFloat(m[2], 64); err == nil {
			row.score = s
		}
		for _, fm := range mariadbFixPattern.FindAllStringSubmatch(m[3], -1) {
			parts, ok := cleanVersionParts(fm[1])
			if !ok {
				continue
			}
			row.fixes = append(row.fixes, mariadbFix{version: fm[1], parts: parts, date: fm[2]})
		}
		rows = append(rows, row)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("%s: no CVE rows — is this MariaDB's community-server.md fixed-CVE table?", path)
	}
	return mariadbIndex(rows), nil
}

// mariadbSeries is a release's major.minor series ("10.11").
func mariadbSeries(parts []int) [2]int {
	var s [2]int
	copy(s[:], parts)
	return s
}

func mariadbIndex(rows []mariadbCVE) *Index {
	// lastFix is the newest fix date the table records for each series —
	// how long that series was still getting security releases.
	lastFix := map[[2]int]string{}
	for _, r := range rows {
		for _, fx := range r.fixes {
			s := mariadbSeries(fx.parts)
			if fx.date > lastFix[s] {
				lastFix[s] = fx.date
			}
		}
	}
	allSeries := make([][2]int, 0, len(lastFix))
	for s := range lastFix {
		allSeries = append(allSeries, s)
	}
	slices.SortFunc(allSeries, func(a, b [2]int) int { return comparePartsSlices(a[:], b[:]) })

	idx := &Index{byProduct: map[string][]Finding{}, vendorCVEs: map[string]map[string]bool{"mariadb": {}}}
	for _, r := range rows {
		if len(r.fixes) == 0 {
			continue
		}
		idx.vendorCVEs["mariadb"][r.id] = true
		rating := CVSS{}
		if r.score > 0 {
			rating = CVSS{Version: "3.1", Score: r.score, Severity: cvssV3Severity(r.score)}
		}
		fixedIn := make([]string, 0, len(r.fixes))
		firstDate := ""
		fixedSeries := map[[2]int]mariadbFix{}
		for _, fx := range r.fixes {
			fixedIn = append(fixedIn, fx.version)
			if fx.date != "" && (firstDate == "" || fx.date < firstDate) {
				firstDate = fx.date
			}
			s := mariadbSeries(fx.parts)
			if prev, ok := fixedSeries[s]; !ok || comparePartsSlices(fx.parts, prev.parts) < 0 {
				fixedSeries[s] = fx
			}
		}
		title := "Fixed in MariaDB Community Server " + strings.Join(fixedIn, ", ")
		base := Finding{
			Source: mariadbSource, AdvisoryID: r.id, CVEIDs: []string{r.id},
			Title: title, MatchedName: "MariaDB Community Server", CVSS: rating,
		}

		// A series with its own fix: vulnerable from the series' first
		// release up to that fix.
		for s, fx := range fixedSeries {
			f := base
			f.FixedVersion = fx.version
			f.RangeText = fmt.Sprintf("%d.%d before %s", s[0], s[1], fx.version)
			f.rng = versionRange{Lo: s[:], LoInclusive: true, Hi: fx.parts}
			idx.byProduct["mariadb"] = append(idx.byProduct["mariadb"], f)
		}

		// A series with no fix of its own is unaffected while it was still
		// being maintained — MariaDB fixes every live series at once. One
		// whose last security release predates this CVE's first fix had
		// already ended: it gets no fix, so every release of it is flagged
		// against the lowest fix in a newer series.
		if firstDate == "" {
			continue
		}
		for _, s := range allSeries {
			if _, ok := fixedSeries[s]; ok || lastFix[s] >= firstDate {
				continue
			}
			var upgrade *mariadbFix
			for _, fx := range r.fixes {
				if comparePartsSlices(fx.parts, s[:]) > 0 && (upgrade == nil || comparePartsSlices(fx.parts, upgrade.parts) < 0) {
					upgrade = &fx
				}
			}
			if upgrade == nil {
				continue
			}
			f := base
			f.FixedVersion = upgrade.version
			f.FixStatus = fmt.Sprintf("no fix in %d.%d (series no longer maintained)", s[0], s[1])
			f.RangeText = fmt.Sprintf("%d.%d, all releases", s[0], s[1])
			f.rng = versionRange{Lo: s[:], LoInclusive: true, Hi: []int{s[0], s[1] + 1}}
			idx.byProduct["mariadb"] = append(idx.byProduct["mariadb"], f)
		}
	}
	return idx
}

// cvssV3Severity is CVSS v3's own qualitative rating for a base score.
func cvssV3Severity(score float64) string {
	switch {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	}
	return "NONE"
}
