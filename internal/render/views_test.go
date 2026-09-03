// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import "testing"

func findRow(rows [][]string, idCol int, id string) []string {
	for _, r := range rows {
		if r[idCol] == id {
			return r
		}
	}
	return nil
}

func TestCompactRows(t *testing.T) {
	_, rows := compactRows(sampleReport())
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
	_, rows := compactRows(sampleReport())
	row := findRow(rows, 0, "jira-b")
	if row[6] != "-" {
		t.Fatalf("got %q, want \"-\" for a target with no Reason", row[6])
	}
}

func TestLifecycleRowsShowsDatesAndDaysRemaining(t *testing.T) {
	_, rows := lifecycleRows(sampleReport())
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
	_, rows := lifecycleRows(sampleReport())
	row := findRow(rows, 0, "confluence-a")
	if row[3] != "-" || row[5] != "-" {
		t.Fatalf("got %+v, want \"-\" for eol and days-to-eol", row)
	}
}

func TestDriftRowsJoinsObservationVersion(t *testing.T) {
	_, rows := driftRows(sampleReport())
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
	_, rows := driftRows(r)
	row := findRow(rows, 0, "jira-a")
	if row[2] != "-" {
		t.Fatalf("got %q, want \"-\" when the observation can't be found", row[2])
	}
}

func TestFleetRowsGroupsByProductAndVersion(t *testing.T) {
	_, rows := fleetRows(sampleReport())
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
	if unknown[2] != "1" || unknown[3] != "down" {
		t.Fatalf("got %+v", unknown)
	}
}

func TestFleetRowsSortedByProductThenVersion(t *testing.T) {
	_, rows := fleetRows(sampleReport())
	for i := 1; i < len(rows); i++ {
		prev, cur := rows[i-1], rows[i]
		if prev[0] > cur[0] || (prev[0] == cur[0] && prev[1] > cur[1]) {
			t.Fatalf("rows not sorted: %+v before %+v", prev, cur)
		}
	}
}

func TestViewRowsUnknownViewErrors(t *testing.T) {
	_, _, err := viewRows(View("bogus"), sampleReport())
	if err == nil {
		t.Fatal("expected an error for an unknown view")
	}
}

func TestViewRowsEmptyDefaultsToCompact(t *testing.T) {
	wantHeaders, wantRows := compactRows(sampleReport())
	gotHeaders, gotRows, err := viewRows("", sampleReport())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gotHeaders) != len(wantHeaders) || len(gotRows) != len(wantRows) {
		t.Fatalf("empty view did not default to compact: got %d headers/%d rows, want %d/%d",
			len(gotHeaders), len(gotRows), len(wantHeaders), len(wantRows))
	}
}
