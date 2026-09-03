// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EpicMorg/enodia/internal/evaluate"
	"github.com/EpicMorg/enodia/internal/render"
	"github.com/EpicMorg/enodia/internal/resolver"
)

func setExportFlags(t *testing.T, from, format, output string) {
	t.Helper()
	prevFrom, prevFormat, prevOut := exportFromFlag, exportFormatFlag, exportOutputFlag
	exportFromFlag, exportFormatFlag, exportOutputFlag = from, format, output
	t.Cleanup(func() { exportFromFlag, exportFormatFlag, exportOutputFlag = prevFrom, prevFormat, prevOut })
}

func TestRunExportCmdJSON(t *testing.T) {
	dir := t.TempDir()
	invPath := filepath.Join(dir, "inv.jsonl")
	writeFile(t, invPath, `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"jira","version":"10.3.1","normalized":"10.3.1","collectedAt":"2026-01-01T00:00:00Z"}
`)
	withFakeResolver(t, fakeSource{cycles: []resolver.Cycle{{Cycle: "10.3", Latest: "10.3.2"}}})
	setExportFlags(t, invPath, "json", "-")

	cmd, stdout, _ := testCmd(t)
	if err := runExportCmd(cmd, nil); err != nil {
		t.Fatalf("runExportCmd: %v", err)
	}

	var got render.Report
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, stdout.String())
	}
	if len(got.Assessments) != 1 || got.Assessments[0].ID != "x" || got.Assessments[0].Patch != evaluate.PatchBehind {
		t.Fatalf("got %+v", got)
	}
}

func TestRunExportCmdPrometheus(t *testing.T) {
	dir := t.TempDir()
	invPath := filepath.Join(dir, "inv.jsonl")
	writeFile(t, invPath, `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"generic","version":"1.0","normalized":"1.0","collectedAt":"2026-01-01T00:00:00Z"}
`)
	withFakeResolver(t, fakeSource{})
	setExportFlags(t, invPath, "prometheus", "-")

	cmd, stdout, _ := testCmd(t)
	if err := runExportCmd(cmd, nil); err != nil {
		t.Fatalf("runExportCmd: %v", err)
	}
	if !strings.Contains(stdout.String(), "enodia_target_info") {
		t.Fatalf("got %q", stdout.String())
	}
}

func TestRunExportCmdHTML(t *testing.T) {
	dir := t.TempDir()
	invPath := filepath.Join(dir, "inv.jsonl")
	writeFile(t, invPath, `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"generic","version":"1.0","normalized":"1.0","collectedAt":"2026-01-01T00:00:00Z"}
`)
	withFakeResolver(t, fakeSource{})
	setExportFlags(t, invPath, "html", "-")

	cmd, stdout, _ := testCmd(t)
	if err := runExportCmd(cmd, nil); err != nil {
		t.Fatalf("runExportCmd: %v", err)
	}
	if !strings.Contains(stdout.String(), "<!doctype html>") {
		t.Fatalf("got %q", stdout.String())
	}
}

func TestRunExportCmdUnsupportedFormatIsBadArgument(t *testing.T) {
	setExportFlags(t, "", "yaml", "-")

	cmd, _, _ := testCmd(t)
	err := runExportCmd(cmd, nil)
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 2 {
		t.Fatalf("got %v, want ExitError{Code:2}", err)
	}
}

func TestRunExportCmdWritesToFile(t *testing.T) {
	dir := t.TempDir()
	invPath := filepath.Join(dir, "inv.jsonl")
	writeFile(t, invPath, `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"generic","version":"1.0","normalized":"1.0","collectedAt":"2026-01-01T00:00:00Z"}
`)
	withFakeResolver(t, fakeSource{})
	outPath := filepath.Join(dir, "out.json")
	setExportFlags(t, invPath, "json", outPath)

	cmd, stdout, _ := testCmd(t)
	if err := runExportCmd(cmd, nil); err != nil {
		t.Fatalf("runExportCmd: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected nothing on stdout when --output is a file, got %q", stdout.String())
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var got render.Report
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("output file is not valid JSON: %v", err)
	}
	if len(got.Assessments) != 1 {
		t.Fatalf("got %+v", got)
	}
}
