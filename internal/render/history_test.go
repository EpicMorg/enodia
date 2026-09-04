// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/EpicMorg/enodia/internal/evaluate"
)

func sampleHistoryReport() HistoryReport {
	day1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	return HistoryReport{
		GeneratedAt: day2,
		Tool:        "enodia/test",
		Timelines: []Timeline{
			{
				ID: "jira-a", Product: "jira",
				Points: []TimelinePoint{
					{AsOf: day1, Version: "10.3.1", Assessment: evaluate.Assessment{
						ID: "jira-a", Patch: evaluate.PatchBehind, Lifecycle: evaluate.LifecycleActive, Branch: evaluate.BranchLatest,
						PatchSeverity: evaluate.SeverityWarn,
					}},
					{AsOf: day2, Version: "10.3.2", Assessment: evaluate.Assessment{
						ID: "jira-a", Patch: evaluate.PatchCurrent, Lifecycle: evaluate.LifecycleActive, Branch: evaluate.BranchLatest,
					}},
				},
			},
			{
				ID: "unknown-target", Product: "generic",
				Points: []TimelinePoint{
					{AsOf: day1, Assessment: evaluate.Assessment{ID: "unknown-target", Reason: evaluate.ReasonProbeFailed}},
				},
			},
		},
	}
}

func TestHistoryTableShowsOneRowPerPoint(t *testing.T) {
	var buf bytes.Buffer
	if err := HistoryTable(&buf, sampleHistoryReport()); err != nil {
		t.Fatalf("HistoryTable: %v", err)
	}
	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	// header + 2 points for jira-a + 1 point for unknown-target
	if len(lines) != 4 {
		t.Fatalf("got %d lines, want 4:\n%s", len(lines), out)
	}
	if !strings.Contains(out, "2026-01-01") || !strings.Contains(out, "2026-01-02") {
		t.Fatalf("missing expected dates:\n%s", out)
	}
	if !strings.Contains(out, "10.3.1") || !strings.Contains(out, "10.3.2") {
		t.Fatalf("missing expected versions:\n%s", out)
	}
}

func TestHistoryTableMissingVersionIsDash(t *testing.T) {
	var buf bytes.Buffer
	if err := HistoryTable(&buf, sampleHistoryReport()); err != nil {
		t.Fatalf("HistoryTable: %v", err)
	}
	if !strings.Contains(buf.String(), "unknown-target") {
		t.Fatalf("missing unknown-target row:\n%s", buf.String())
	}
	// The failed-probe point has no Version set, so its row must show "-".
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "unknown-target") && !strings.Contains(line, "-") {
			t.Fatalf("expected a dash placeholder in row: %q", line)
		}
	}
}

func TestHistoryTableEmptyReport(t *testing.T) {
	var buf bytes.Buffer
	if err := HistoryTable(&buf, HistoryReport{}); err != nil {
		t.Fatalf("HistoryTable: %v", err)
	}
	if !strings.Contains(buf.String(), "SEVERITY") {
		t.Fatalf("expected at least the header row, got %q", buf.String())
	}
}

func TestHistoryJSONRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if err := HistoryJSON(&buf, sampleHistoryReport()); err != nil {
		t.Fatalf("HistoryJSON: %v", err)
	}
	var got HistoryReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if len(got.Timelines) != 2 || len(got.Timelines[0].Points) != 2 {
		t.Fatalf("got %+v", got)
	}
}

func TestHistoryJSONUsesCamelCaseFields(t *testing.T) {
	var buf bytes.Buffer
	if err := HistoryJSON(&buf, sampleHistoryReport()); err != nil {
		t.Fatalf("HistoryJSON: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"generatedAt", "tool", "timelines"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("missing field %q", field)
		}
	}
	timelines := raw["timelines"].([]any)
	first := timelines[0].(map[string]any)
	if _, ok := first["points"]; !ok {
		t.Errorf("missing \"points\" in %v", first)
	}
	points := first["points"].([]any)
	point := points[0].(map[string]any)
	for _, field := range []string{"asOf", "version", "assessment"} {
		if _, ok := point[field]; !ok {
			t.Errorf("missing point field %q in %v", field, point)
		}
	}
}
