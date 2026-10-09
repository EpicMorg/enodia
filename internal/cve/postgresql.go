// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// postgresqlSource is Finding.Source for the PostgreSQL project's own
// security table.
const postgresqlSource = "postgresql"

var (
	pgRowPattern  = regexp.MustCompile(`(?s)<tr>(.*?)</tr>`)
	pgCellPattern = regexp.MustCompile(`(?s)<td>(.*?)</td>`)
	pgTagPattern  = regexp.MustCompile(`<[^>]+>`)
	pgCVEPattern  = regexp.MustCompile(`^CVE-\d{4}-\d+$`)
	pgNewsPattern = regexp.MustCompile(`href="(/about/news/[^"]+)"`)
	pgScore       = regexp.MustCompile(`>(\d+(?:\.\d+)?)</a>`)
)

type pgRow struct {
	id, component, title, announcement string
	score                              float64
	affected                           []pgMajor
	fixed                              map[pgMajor][]int
}

// pgMajor is a PostgreSQL major version: "17", or before 10 "9.6".
type pgMajor [2]int

func (m pgMajor) String() string {
	if m[0] >= 10 {
		return strconv.Itoa(m[0])
	}
	return fmt.Sprintf("%d.%d", m[0], m[1])
}

func (m pgMajor) lo() []int { return []int{m[0], m[1]} }

func (m pgMajor) next() []int {
	if m[0] >= 10 {
		return []int{m[0] + 1}
	}
	return []int{m[0], m[1] + 1}
}

func pgMajorOf(parts []int) (pgMajor, bool) {
	switch {
	case len(parts) == 0:
		return pgMajor{}, false
	case parts[0] >= 10:
		return pgMajor{parts[0], 0}, true
	case len(parts) >= 2:
		return pgMajor{parts[0], parts[1]}, true
	}
	return pgMajor{}, false
}

// LoadPostgreSQL reads the PostgreSQL project's security table
// (cve.postgresql.path): https://www.postgresql.org/support/security/
// saved as is, or a directory holding it and any of the per-major pages
// (/support/security/13/, …) for majors no longer supported. Each row
// names the affected majors and the release that fixes each. See
// docs/DECISIONS.md D71.
func LoadPostgreSQL(path string) (*Index, error) {
	files := []string{path}
	if st, err := os.Stat(path); err != nil {
		return nil, err
	} else if st.IsDir() {
		files, err = filepath.Glob(filepath.Join(path, "*.htm*"))
		if err != nil {
			return nil, err
		}
	}
	rows := map[string]pgRow{}
	var order []string // newest first, as the page lists them
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for _, r := range parsePGRows(string(raw)) {
			prev, seen := rows[r.id]
			if !seen {
				order = append(order, r.id)
				rows[r.id] = r
				continue
			}
			// The main page names only the majors supported today; a
			// per-major page names that major too. Keep every one named.
			for _, m := range r.affected {
				if !slices.Contains(prev.affected, m) {
					prev.affected = append(prev.affected, m)
				}
			}
			for m, fx := range r.fixed {
				prev.fixed[m] = fx
			}
			rows[r.id] = prev
		}
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("%s: no CVE rows — is this https://www.postgresql.org/support/security/ saved as HTML?", path)
	}
	return pgIndex(rows, order), nil
}

func pgText(s string) string {
	return strings.Join(strings.Fields(html.UnescapeString(pgTagPattern.ReplaceAllString(s, " "))), " ")
}

func parsePGRows(page string) []pgRow {
	var out []pgRow
	for _, tr := range pgRowPattern.FindAllStringSubmatch(page, -1) {
		cells := pgCellPattern.FindAllStringSubmatch(tr[1], -1)
		if len(cells) != 5 {
			continue
		}
		ref := strings.Fields(pgText(cells[0][1]))
		if len(ref) == 0 || !pgCVEPattern.MatchString(ref[0]) {
			continue
		}
		r := pgRow{id: ref[0], title: strings.TrimSuffix(pgText(cells[4][1]), " more details"), fixed: map[pgMajor][]int{}}
		if m := pgNewsPattern.FindStringSubmatch(cells[0][1]); m != nil {
			r.announcement = m[1]
		}
		comp := pgText(cells[3][1])
		if m := pgScore.FindStringSubmatch(cells[3][1]); m != nil {
			r.score, _ = strconv.ParseFloat(m[1], 64)
			if i := strings.Index(comp, m[1]); i > 0 {
				comp = strings.TrimSpace(comp[:i])
			}
		}
		r.component = comp
		for _, a := range strings.Split(pgText(cells[1][1]), ",") {
			if parts, ok := cleanVersionParts(a); ok {
				if m, ok := pgMajorOf(parts); ok {
					r.affected = append(r.affected, m)
				}
			}
		}
		for _, fx := range strings.Split(pgText(cells[2][1]), ",") {
			if parts, ok := cleanVersionParts(fx); ok {
				if m, ok := pgMajorOf(parts); ok {
					r.fixed[m] = parts
				}
			}
		}
		if len(r.affected) > 0 {
			out = append(out, r)
		}
	}
	return out
}

func pgIndex(rows map[string]pgRow, order []string) *Index {
	// Every major the table names anywhere: its verdict covers those.
	named := map[pgMajor]bool{}
	// The oldest major each release announcement fixed: the oldest one
	// still supported when that announcement's CVEs were published.
	oldestAt := map[string]pgMajor{}
	for _, r := range rows {
		for _, m := range r.affected {
			named[m] = true
			if o, ok := oldestAt[r.announcement]; !ok || comparePartsSlices(m.lo(), o.lo()) < 0 {
				oldestAt[r.announcement] = m
			}
		}
	}
	majors := make([]pgMajor, 0, len(named))
	for m := range named {
		majors = append(majors, m)
	}
	slices.SortFunc(majors, func(a, b pgMajor) int { return comparePartsSlices(a.lo(), b.lo()) })

	idx := &Index{
		byProduct:    map[string][]Finding{},
		vendorCVEs:   map[string]map[string]bool{"postgresql": {}},
		vendorCovers: map[string]func([]int) bool{},
	}
	idx.vendorCovers["postgresql"] = func(parts []int) bool {
		m, ok := pgMajorOf(parts)
		return ok && named[m]
	}
	for _, id := range order {
		r := rows[id]
		idx.vendorCVEs["postgresql"][id] = true
		// An installer or RPM bug: about one build of a release, not the
		// release itself.
		if r.component == "packaging" {
			continue
		}
		base := Finding{
			Source: postgresqlSource, AdvisoryID: id, CVEIDs: []string{id}, Title: r.title,
			MatchedName: "PostgreSQL " + r.component,
			AdvisoryURL: "https://www.postgresql.org/support/security/" + id + "/",
		}
		if r.score > 0 {
			base.CVSS = CVSS{Version: "3.1", Score: r.score, Severity: cvssV3Severity(r.score)}
		}
		var lowestFix []int
		for _, m := range r.affected {
			f := base
			f.rng = versionRange{Lo: m.lo(), LoInclusive: true, Hi: m.next()}
			if fx, ok := r.fixed[m]; ok {
				f.rng.Hi = fx
				f.FixedVersion = joinParts(fx)
				f.RangeText = m.String() + " before " + f.FixedVersion
				if lowestFix == nil || comparePartsSlices(fx, lowestFix) < 0 {
					lowestFix = fx
				}
			} else {
				f.RangeText = m.String() + ", all releases"
				f.FixStatus = "no fix listed for " + m.String()
			}
			idx.byProduct["postgresql"] = append(idx.byProduct["postgresql"], f)
		}
		// Majors already out of support when this CVE was published aren't
		// listed. When the bug reaches back to the oldest major still
		// supported then, the ended ones older than it almost surely have
		// it too, and will never get a fix: every release of them is
		// flagged, with the lowest fix in a supported major to move to.
		oldest, ok := oldestAt[r.announcement]
		if !ok || !slices.Contains(r.affected, oldest) {
			continue
		}
		for _, m := range majors {
			if comparePartsSlices(m.lo(), oldest.lo()) >= 0 {
				break
			}
			f := base
			f.rng = versionRange{Lo: m.lo(), LoInclusive: true, Hi: m.next()}
			f.RangeText = m.String() + ", all releases"
			f.FixStatus = fmt.Sprintf("no fix in %s (major no longer supported)", m)
			if lowestFix != nil {
				f.FixedVersion = joinParts(lowestFix)
			}
			idx.byProduct["postgresql"] = append(idx.byProduct["postgresql"], f)
		}
	}
	return idx
}
