// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"sort"
	"strconv"
	"strings"

	"github.com/EpicMorg/enodia/internal/evaluate"
)

// Each view function returns a header row, the data rows, and a RowTone per
// row for one focus. Both Table (text, which ignores tones — plain text has
// no color) and HTML render from the same rows, so the two never drift
// apart; CDN-mode HTML is the one renderer that actually uses tones, to
// pick a Bootstrap contextual table class per row.

// RowTone is a row's at-a-glance color category, deliberately its own type
// rather than a reuse of evaluate.Severity: a fleet row's tone comes
// straight from an Observation's reachability, a fact (D7), not from any
// policy judgement, so giving it a "Severity" would blur that line even
// though both end up picking the same Bootstrap class.
type RowTone string

const (
	ToneNone RowTone = "" // no strong opinion — CDN mode leaves the row unclassed
	ToneGood RowTone = "good"
	ToneInfo RowTone = "info"
	ToneWarn RowTone = "warn"
	ToneBad  RowTone = "bad"
)

// severityTone maps an evaluate.Severity to the RowTone that carries the
// same traffic-light meaning, for the views built from Assessments.
func severityTone(s evaluate.Severity) RowTone {
	switch s {
	case evaluate.SeverityFail:
		return ToneBad
	case evaluate.SeverityWarn:
		return ToneWarn
	case evaluate.SeverityInfo:
		return ToneInfo
	default:
		return ToneGood
	}
}

func compactRows(r Report) (headers []string, rows [][]string, tones []RowTone) {
	headers = []string{"ID", "PRODUCT", "PATCH", "LIFECYCLE", "BRANCH", "SEVERITY", "REASON"}
	for _, a := range r.Assessments {
		rows = append(rows, []string{
			a.ID, a.Product, string(a.Patch), string(a.Lifecycle), string(a.Branch),
			string(a.OverallSeverity()), firstNonEmpty(string(a.Reason), "-"),
		})
		tones = append(tones, severityTone(a.OverallSeverity()))
	}
	return headers, rows, tones
}

// lifecycleRows tones by LifecycleSeverity specifically, not OverallSeverity:
// this view is focused on the lifecycle axis, so a row is red because ITS
// lifecycle boundary is critical, not because some unrelated branch finding
// happened to be worse.
func lifecycleRows(r Report) (headers []string, rows [][]string, tones []RowTone) {
	headers = []string{"ID", "PRODUCT", "LIFECYCLE", "EOL", "SUPPORT-ENDS", "DAYS-TO-EOL"}
	for _, a := range r.Assessments {
		rows = append(rows, []string{
			a.ID, a.Product, string(a.Lifecycle),
			formatDate(a.EOLDate), formatDate(a.SupportEnds), daysUntil(a.EOLDate, r.AsOf),
		})
		tones = append(tones, severityTone(a.LifecycleSeverity))
	}
	return headers, rows, tones
}

// driftRows tones by PatchSeverity specifically, for the same reason
// lifecycleRows uses LifecycleSeverity: this view is about the patch axis.
func driftRows(r Report) (headers []string, rows [][]string, tones []RowTone) {
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
		tones = append(tones, severityTone(a.PatchSeverity))
	}
	return headers, rows, tones
}

// fleetRows groups observations by product, installed version and status,
// so an operator can see both version spread and reachability across a
// fleet at a glance — "table of versions + which are up" is this view,
// not a separate one. Deliberately built from Observations alone, not
// Assessments (D7: reachability is a fact collect already recorded, not a
// verdict): this is the one view that still works with zero
// lifecycle-resolver connectivity. Tones follow the same rule: ToneGood/
// ToneBad from Observation.OK(), never a policy Severity — there is no
// "warning" state here, only reachable or not.
//
// STATUS is grouped alongside product+version, not folded into a single
// "(unknown)" bucket: two failed instances of the same product with
// different ErrorKinds (say, one unreachable, one auth) are different
// operational situations and must not be merged into one row.
func fleetRows(r Report) (headers []string, rows [][]string, tones []RowTone) {
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
		tone := ToneGood
		if k.status != "ok" {
			tone = ToneBad
		}
		tones = append(tones, tone)
	}
	return headers, rows, tones
}
