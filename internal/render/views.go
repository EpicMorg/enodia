// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"sort"
	"strconv"
	"strings"
)

// Each view function returns a header row and the data rows for one focus.
// Both Table (text) and HTML render from the same rows, so the two never
// drift apart.

func compactRows(r Report) (headers []string, rows [][]string) {
	headers = []string{"ID", "PRODUCT", "PATCH", "LIFECYCLE", "BRANCH", "SEVERITY", "REASON"}
	for _, a := range r.Assessments {
		rows = append(rows, []string{
			a.ID, a.Product, string(a.Patch), string(a.Lifecycle), string(a.Branch),
			string(a.OverallSeverity()), firstNonEmpty(string(a.Reason), "-"),
		})
	}
	return headers, rows
}

func lifecycleRows(r Report) (headers []string, rows [][]string) {
	headers = []string{"ID", "PRODUCT", "LIFECYCLE", "EOL", "SUPPORT-ENDS", "DAYS-TO-EOL"}
	for _, a := range r.Assessments {
		rows = append(rows, []string{
			a.ID, a.Product, string(a.Lifecycle),
			formatDate(a.EOLDate), formatDate(a.SupportEnds), daysUntil(a.EOLDate, r.AsOf),
		})
	}
	return headers, rows
}

func driftRows(r Report) (headers []string, rows [][]string) {
	headers = []string{"ID", "PRODUCT", "CURRENT", "LATEST", "CYCLE", "PATCH"}
	obsByID := indexObservations(r.Observations)
	for _, a := range r.Assessments {
		current := "-"
		if o, ok := obsByID[a.ID]; ok {
			current = firstNonEmpty(o.Normalized, o.Version, "-")
		}
		rows = append(rows, []string{
			a.ID, a.Product, current,
			firstNonEmpty(a.LatestInCycle, "-"), firstNonEmpty(a.MatchedCycle, "-"), string(a.Patch),
		})
	}
	return headers, rows
}

// fleetRows groups observations by product, installed version and status,
// so an operator can see both version spread and reachability across a
// fleet at a glance — "table of versions + which are up" is this view,
// not a separate one. Deliberately built from Observations alone, not
// Assessments (D7: reachability is a fact collect already recorded, not a
// verdict): this is the one view that still works with zero
// lifecycle-resolver connectivity.
//
// STATUS is grouped alongside product+version, not folded into a single
// "(unknown)" bucket: two failed instances of the same product with
// different ErrorKinds (say, one unreachable, one auth) are different
// operational situations and must not be merged into one row.
func fleetRows(r Report) (headers []string, rows [][]string) {
	headers = []string{"PRODUCT", "VERSION", "STATUS", "COUNT", "INSTANCES"}

	type key struct{ product, version, status string }
	groups := map[key][]string{}
	for _, o := range r.Observations {
		version := firstNonEmpty(o.Normalized, o.Version, "(unknown)")
		status := "ok"
		if !o.OK() {
			status = firstNonEmpty(o.ErrorKind, "error")
		}
		k := key{o.Product, version, status}
		groups[k] = append(groups[k], o.ID)
	}

	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].product != keys[j].product {
			return keys[i].product < keys[j].product
		}
		if keys[i].version != keys[j].version {
			return keys[i].version < keys[j].version
		}
		return keys[i].status < keys[j].status
	})

	for _, k := range keys {
		ids := groups[k]
		sort.Strings(ids)
		rows = append(rows, []string{k.product, k.version, k.status, strconv.Itoa(len(ids)), strings.Join(ids, ", ")})
	}
	return headers, rows
}
