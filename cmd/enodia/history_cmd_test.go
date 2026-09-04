// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/EpicMorg/enodia/internal/render"
	"github.com/EpicMorg/enodia/internal/resolver"
)

func dateFlagForCmdTest(s string) *resolver.Flag {
	tm, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return &resolver.Flag{Bool: true, IsDate: true, Date: tm}
}

func setHistoryFlags(t *testing.T, dir, format, output string) {
	t.Helper()
	prevDir, prevFormat, prevOutput := historyDirFlag, historyFormatFlag, historyOutputFlag
	historyDirFlag, historyFormatFlag, historyOutputFlag = dir, format, output
	t.Cleanup(func() { historyDirFlag, historyFormatFlag, historyOutputFlag = prevDir, prevFormat, prevOutput })
}

func TestRunHistoryCmdRequiresDir(t *testing.T) {
	setHistoryFlags(t, "", "table", "-")
	cmd, _, _ := testCmd(t)
	err := runHistoryCmd(cmd, nil)
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 2 {
		t.Fatalf("got %v, want ExitError{Code:2}", err)
	}
}

func TestRunHistoryCmdUnsupportedFormat(t *testing.T) {
	setHistoryFlags(t, t.TempDir(), "xml", "-")
	cmd, _, _ := testCmd(t)
	err := runHistoryCmd(cmd, nil)
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 2 {
		t.Fatalf("got %v, want ExitError{Code:2}", err)
	}
}

func TestRunHistoryCmdMissingDirIsInternalError(t *testing.T) {
	setHistoryFlags(t, filepath.Join(t.TempDir(), "nope"), "table", "-")
	cmd, _, _ := testCmd(t)
	err := runHistoryCmd(cmd, nil)
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 1 {
		t.Fatalf("got %v, want ExitError{Code:1}", err)
	}
}

func TestRunHistoryCmdTable(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "day1.jsonl"), `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"generic","version":"1.0","normalized":"1.0","collectedAt":"2026-01-01T00:00:00Z"}
`)
	writeFile(t, filepath.Join(dir, "day2.jsonl"), `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-02T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"generic","version":"1.1","normalized":"1.1","collectedAt":"2026-01-02T00:00:00Z"}
`)
	withFakeResolver(t, fakeSource{})
	setHistoryFlags(t, dir, "table", "-")

	cmd, stdout, _ := testCmd(t)
	if err := runHistoryCmd(cmd, nil); err != nil {
		t.Fatalf("runHistoryCmd: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "2026-01-01") || !strings.Contains(out, "2026-01-02") {
		t.Fatalf("got %q", out)
	}
	if !strings.Contains(out, "1.0") || !strings.Contains(out, "1.1") {
		t.Fatalf("got %q", out)
	}
}

func TestRunHistoryCmdJSON(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "day1.jsonl"), `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"generic","version":"1.0","normalized":"1.0","collectedAt":"2026-01-01T00:00:00Z"}
`)
	withFakeResolver(t, fakeSource{})
	setHistoryFlags(t, dir, "json", "-")

	cmd, stdout, _ := testCmd(t)
	if err := runHistoryCmd(cmd, nil); err != nil {
		t.Fatalf("runHistoryCmd: %v", err)
	}
	var got render.HistoryReport
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, stdout.String())
	}
	if len(got.Timelines) != 1 || got.Timelines[0].ID != "x" {
		t.Fatalf("got %+v", got)
	}
}

func TestRunHistoryCmdWritesToFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "day1.jsonl"), `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"generic","version":"1.0","normalized":"1.0","collectedAt":"2026-01-01T00:00:00Z"}
`)
	withFakeResolver(t, fakeSource{})
	outPath := filepath.Join(dir, "out.json")
	setHistoryFlags(t, dir, "json", outPath)

	cmd, stdout, _ := testCmd(t)
	if err := runHistoryCmd(cmd, nil); err != nil {
		t.Fatalf("runHistoryCmd: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected nothing on stdout when --output is a file, got %q", stdout.String())
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var got render.HistoryReport
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("output file is not valid JSON: %v", err)
	}
	if len(got.Timelines) != 1 {
		t.Fatalf("got %+v", got)
	}
}

func TestRunHistoryCmdUsesEachDaysOwnAsOf(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "day1.jsonl"), `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"jira","version":"10.3.1","normalized":"10.3.1","collectedAt":"2026-01-01T00:00:00Z"}
`)
	writeFile(t, filepath.Join(dir, "day2.jsonl"), `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-06-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"jira","version":"10.3.1","normalized":"10.3.1","collectedAt":"2026-06-01T00:00:00Z"}
`)
	withFakeResolver(t, fakeSource{cycles: []resolver.Cycle{
		{Cycle: "10.3", Latest: "10.3.2", EOL: dateFlagForCmdTest("2026-03-01")},
	}})
	setHistoryFlags(t, dir, "json", "-")

	cmd, stdout, _ := testCmd(t)
	if err := runHistoryCmd(cmd, nil); err != nil {
		t.Fatalf("runHistoryCmd: %v", err)
	}
	var got render.HistoryReport
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, stdout.String())
	}
	points := got.Timelines[0].Points
	if len(points) != 2 {
		t.Fatalf("got %+v", points)
	}
	if points[0].Assessment.Lifecycle != "active" {
		t.Errorf("day1: got lifecycle %q, want active", points[0].Assessment.Lifecycle)
	}
	if points[1].Assessment.Lifecycle != "eol" {
		t.Errorf("day2: got lifecycle %q, want eol", points[1].Assessment.Lifecycle)
	}
}
