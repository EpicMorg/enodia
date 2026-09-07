// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"testing"

	"github.com/EpicMorg/enodia/internal/evaluate"
	"github.com/EpicMorg/enodia/internal/probe"
)

func findRow(rows [][]string, idCol int, id string) []string {
	for _, r := range rows {
		if r[idCol] == id {
			return r
		}
	}
	return nil
}

func findRowIndex(rows [][]string, idCol int, id string) int {
	for i, r := range rows {
		if r[idCol] == id {
			return i
		}
	}
	return -1
}

func TestCompactRows(t *testing.T) {
	_, rows, _ := compactRows(sampleReport())
	if len(rows) != 4 {
		t.Fatalf("got %d rows, want 4", len(rows))
	}
	row := findRow(rows, 0, "down")
	if row == nil {
		t.Fatal("missing row for \"down\"")
	}
	// ID, PRODUCT, PATCH, LIFECYCLE, BRANCH, SEVERITY, REASON
	if row[6] != "probe_failed" {
		t.Fatalf("got reason column %q, want probe_failed", row[6])
	}
}

func TestCompactRowsReasonDefaultsToDash(t *testing.T) {
	_, rows, _ := compactRows(sampleReport())
	row := findRow(rows, 0, "jira-b")
	if row[6] != "-" {
		t.Fatalf("got %q, want \"-\" for a target with no Reason", row[6])
	}
}

// compactRows tones by OverallSeverity: jira-a is warn (lifecycle warn),
// jira-b is warn too (lifecycle warn even though patch is current), "down"
// is warn (probe_failed's floor), confluence-a is warn (branch warn).
// sampleReport carries no fail-severity assessment, so ToneBad is checked
// separately below via a synthetic report.
func TestCompactRowsTonesFollowOverallSeverity(t *testing.T) {
	_, rows, tones := compactRows(sampleReport())
	i := findRowIndex(rows, 0, "jira-a")
	if tones[i] != ToneWarn {
		t.Fatalf("got tone %q for jira-a, want warn", tones[i])
	}
}

func TestCompactRowsFailSeverityIsToneBad(t *testing.T) {
	r := sampleReport()
	r.Assessments[0].PatchSeverity = evaluate.SeverityFail
	_, rows, tones := compactRows(r)
	i := findRowIndex(rows, 0, "jira-a")
	if tones[i] != ToneBad {
		t.Fatalf("got tone %q, want bad", tones[i])
	}
}

// "down" (index 3, Reason: probe_failed) must not blend into ordinary
// SeverityWarn rows: a target answering 502 or as the wrong service
// entirely is a different kind of problem than a policy-driven warning,
// even though both currently carry the same SeverityWarn.
func TestCompactRowsUnreachableIsToneInfoNotWarn(t *testing.T) {
	_, rows, tones := compactRows(sampleReport())
	i := findRowIndex(rows, 0, "down")
	if tones[i] != ToneInfo {
		t.Fatalf("got tone %q for down (probe_failed), want info", tones[i])
	}
}

// An explicit --fail-on=reason:probe_failed escalates ReasonSeverity to
// SeverityFail — that operator override must win and render Bad, not be
// silently downgraded to the anomaly's usual Info by isUnreachableAnomaly.
func TestCompactRowsEscalatedProbeFailedIsToneBadNotInfo(t *testing.T) {
	r := sampleReport()
	i := findAssessmentIndex(r.Assessments, "down")
	r.Assessments[i].ReasonSeverity = evaluate.SeverityFail
	_, rows, tones := compactRows(r)
	j := findRowIndex(rows, 0, "down")
	if tones[j] != ToneBad {
		t.Fatalf("got tone %q, want bad (escalated via FailOn)", tones[j])
	}
}

func findAssessmentIndex(assessments []evaluate.Assessment, id string) int {
	for i, a := range assessments {
		if a.ID == id {
			return i
		}
	}
	return -1
}

func TestLifecycleRowsShowsDatesAndDaysRemaining(t *testing.T) {
	_, rows, _ := lifecycleRows(sampleReport())
	row := findRow(rows, 0, "jira-a")
	if row == nil {
		t.Fatal("missing row")
	}
	// ID, PRODUCT, LIFECYCLE, EOL, SUPPORT-ENDS, DAYS-TO-EOL
	if row[3] != "2026-03-01" {
		t.Fatalf("got EOL %q, want 2026-03-01", row[3])
	}
	if row[5] != "59" {
		t.Fatalf("got days-to-eol %q, want 59 (2026-01-01 to 2026-03-01)", row[5])
	}
}

func TestLifecycleRowsNoDateIsDash(t *testing.T) {
	_, rows, _ := lifecycleRows(sampleReport())
	row := findRow(rows, 0, "confluence-a")
	if row[3] != "-" || row[5] != "-" {
		t.Fatalf("got %+v, want \"-\" for eol and days-to-eol", row)
	}
}

// lifecycleRows tones by LifecycleSeverity specifically: confluence-a has a
// warn BranchSeverity but SeverityNone LifecycleSeverity, so its lifecycle
// row must read as good, not warn — a row here is about the lifecycle axis
// alone, not "is anything at all wrong with this target".
func TestLifecycleRowsToneIgnoresOtherAxes(t *testing.T) {
	_, rows, tones := lifecycleRows(sampleReport())
	i := findRowIndex(rows, 0, "confluence-a")
	if tones[i] != ToneGood {
		t.Fatalf("got tone %q for confluence-a, want good (its LifecycleSeverity is none)", tones[i])
	}
	j := findRowIndex(rows, 0, "jira-a")
	if tones[j] != ToneWarn {
		t.Fatalf("got tone %q for jira-a, want warn (its LifecycleSeverity is warn)", tones[j])
	}
}

// "down" is unreachable: Lifecycle/Patch are Unknown with a zero-value
// (SeverityNone) axis severity, which must not read as ToneGood — an
// all-dashes row tinted green looks like "no issue" when it actually means
// "no data".
func TestLifecycleRowsUnknownIsToneInfoNotGood(t *testing.T) {
	_, rows, tones := lifecycleRows(sampleReport())
	i := findRowIndex(rows, 0, "down")
	if tones[i] != ToneInfo {
		t.Fatalf("got tone %q for down (LifecycleUnknown), want info", tones[i])
	}
}

func TestDriftRowsUnknownIsToneInfoNotGood(t *testing.T) {
	_, rows, tones := driftRows(sampleReport())
	i := findRowIndex(rows, 0, "down")
	if tones[i] != ToneInfo {
		t.Fatalf("got tone %q for down (PatchUnknown), want info", tones[i])
	}
}

// A target that answers fine but whose cycle the resolver doesn't
// recognize (Reason: cycle_unmatched) is a real gap, not the same anomaly
// as a target that never answered at all ("down") — it must not share
// probe_failed's ToneInfo.
func TestLifecycleRowsCycleUnmatchedIsToneWarnNotInfo(t *testing.T) {
	r := sampleReport()
	i := findAssessmentIndex(r.Assessments, "down")
	r.Assessments[i].Reason = evaluate.ReasonCycleUnmatched
	r.Assessments[i].ReasonSeverity = evaluate.SeverityWarn

	_, rows, tones := lifecycleRows(r)
	j := findRowIndex(rows, 0, "down")
	if tones[j] != ToneWarn {
		t.Fatalf("got tone %q, want warn (cycle_unmatched is a real gap, not an anomaly)", tones[j])
	}
}

// Same case in drift, but with a real observed version present (unlike
// "down"'s actual fixture): CURRENT shows that version, not a dash, while
// LATEST/CYCLE are dashes and PATCH reads unknown — still not the same
// anomaly as an unreachable target, so still ToneWarn, not ToneInfo.
func TestDriftRowsCycleUnmatchedIsToneWarnNotInfo(t *testing.T) {
	r := sampleReport()
	i := findAssessmentIndex(r.Assessments, "down")
	r.Assessments[i].Reason = evaluate.ReasonCycleUnmatched
	r.Assessments[i].ReasonSeverity = evaluate.SeverityWarn
	for k := range r.Observations {
		if r.Observations[k].ID == "down" {
			r.Observations[k] = probe.Observation{ID: "down", Product: "jira", Version: "99.9.9", Normalized: "99.9.9"}
		}
	}

	_, rows, tones := driftRows(r)
	row := findRow(rows, 0, "down")
	if row[2] != "99.9.9" {
		t.Fatalf("got current %q, want the real observed version 99.9.9, not a dash", row[2])
	}
	j := findRowIndex(rows, 0, "down")
	if tones[j] != ToneWarn {
		t.Fatalf("got tone %q, want warn (cycle_unmatched is a real gap, not an anomaly)", tones[j])
	}
}

func TestDriftRowsJoinsObservationVersion(t *testing.T) {
	_, rows, _ := driftRows(sampleReport())
	row := findRow(rows, 0, "jira-a")
	// ID, PRODUCT, CURRENT, LATEST, CYCLE, PATCH
	if row[2] != "10.3.1" {
		t.Fatalf("got current %q, want 10.3.1", row[2])
	}
	if row[3] != "10.3.2" {
		t.Fatalf("got latest %q, want 10.3.2", row[3])
	}
	if row[5] != "behind" {
		t.Fatalf("got patch %q, want behind", row[5])
	}
}

func TestDriftRowsMissingObservationIsDash(t *testing.T) {
	r := sampleReport()
	r.Observations = nil // assessments reference IDs no longer in Observations
	_, rows, _ := driftRows(r)
	row := findRow(rows, 0, "jira-a")
	if row[2] != "-" {
		t.Fatalf("got %q, want \"-\" when the observation can't be found", row[2])
	}
}

func TestFleetRowsGroupsByProductAndVersion(t *testing.T) {
	_, rows, _ := fleetRows(sampleReport())
	// jira has three observations: 10.3.1, 10.3.2, and one failed ("(unknown)").
	var jiraRows [][]string
	for _, r := range rows {
		if r[0] == "jira" {
			jiraRows = append(jiraRows, r)
		}
	}
	if len(jiraRows) != 3 {
		t.Fatalf("got %d jira rows, want 3 (two versions + unknown), rows=%+v", len(jiraRows), rows)
	}

	unknown := findRow(jiraRows, 1, "(unknown)")
	if unknown == nil {
		t.Fatalf("expected a (unknown) version bucket for the failed probe, got %+v", jiraRows)
	}
	if unknown[2] != "unreachable" || unknown[3] != "1" || unknown[4] != "down" {
		t.Fatalf("got %+v", unknown)
	}
}

func TestFleetRowsStatusColumnDistinguishesOKFromFailed(t *testing.T) {
	_, rows, _ := fleetRows(sampleReport())
	ok := findRow(rows, 0, "confluence")
	if ok == nil || ok[2] != "ok" {
		t.Fatalf("expected confluence's successful observation to have STATUS ok, got %+v", ok)
	}
}

func TestFleetRowsTonesAreGoodOrBadOnly(t *testing.T) {
	_, rows, tones := fleetRows(sampleReport())
	i := findRowIndex(rows, 0, "confluence")
	if tones[i] != ToneGood {
		t.Fatalf("got tone %q for confluence's ok row, want good", tones[i])
	}
	j := findRowIndex(rows, 1, "(unknown)")
	if tones[j] != ToneBad {
		t.Fatalf("got tone %q for the failed jira row, want bad", tones[j])
	}
}

func TestFleetRowsSortedByProductThenVersion(t *testing.T) {
	_, rows, _ := fleetRows(sampleReport())
	for i := 1; i < len(rows); i++ {
		prev, cur := rows[i-1], rows[i]
		if prev[0] > cur[0] || (prev[0] == cur[0] && prev[1] > cur[1]) {
			t.Fatalf("rows not sorted: %+v before %+v", prev, cur)
		}
	}
}

func TestViewRowsUnknownViewErrors(t *testing.T) {
	_, _, _, err := viewRows(View("bogus"), sampleReport())
	if err == nil {
		t.Fatal("expected an error for an unknown view")
	}
}

func TestViewRowsEmptyDefaultsToCompact(t *testing.T) {
	wantHeaders, wantRows, _ := compactRows(sampleReport())
	gotHeaders, gotRows, _, err := viewRows("", sampleReport())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gotHeaders) != len(wantHeaders) || len(gotRows) != len(wantRows) {
		t.Fatalf("empty view did not default to compact: got %d headers/%d rows, want %d/%d",
			len(gotHeaders), len(gotRows), len(wantHeaders), len(wantRows))
	}
}
