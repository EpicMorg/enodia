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

func TestRunExportCmdHTMLUsesSettingsCDNAndTheme(t *testing.T) {
	dir := t.TempDir()
	invPath := filepath.Join(dir, "inv.jsonl")
	writeFile(t, invPath, `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"generic","version":"1.0","normalized":"1.0","collectedAt":"2026-01-01T00:00:00Z"}
`)
	withFakeResolver(t, fakeSource{})
	setExportFlags(t, invPath, "html", "-")

	settingsPath := filepath.Join(dir, "settings.yaml")
	writeFile(t, settingsPath, "schemaVersion: 1\nhtml:\n  assets: cdn\n  theme: lumen\n")
	withSettingsFlag(t, settingsPath)

	cmd, stdout, _ := testCmd(t)
	if err := runExportCmd(cmd, nil); err != nil {
		t.Fatalf("runExportCmd: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "dist/lumen/bootstrap.min.css") {
		t.Fatalf("expected settings.yaml's html.theme: lumen to apply, got:\n%s", out)
	}
	if !strings.Contains(out, "needs internet access") {
		t.Fatal("expected the CDN-mode warning banner")
	}
}

func TestRunExportCmdHTMLViewFlagRestrictsToOneSection(t *testing.T) {
	dir := t.TempDir()
	invPath := filepath.Join(dir, "inv.jsonl")
	writeFile(t, invPath, `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"generic","version":"1.0","normalized":"1.0","collectedAt":"2026-01-01T00:00:00Z"}
`)
	withFakeResolver(t, fakeSource{})
	setExportFlags(t, invPath, "html", "-")

	prevView := exportViewFlag
	exportViewFlag = "fleet"
	t.Cleanup(func() { exportViewFlag = prevView })

	cmd, stdout, _ := testCmd(t)
	cmd.Flags().String("view", "", "")
	if err := cmd.Flags().Set("view", "fleet"); err != nil {
		t.Fatal(err)
	}
	if err := runExportCmd(cmd, nil); err != nil {
		t.Fatalf("runExportCmd: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "<h2>Fleet</h2>") {
		t.Fatalf("expected only the Fleet section, got:\n%s", out)
	}
	if strings.Contains(out, "<h2>Compact</h2>") {
		t.Fatalf("--view=fleet still rendered Compact, got:\n%s", out)
	}
}

// settings.yaml's export.default_format applies only when --format was not
// passed on the command line; exportFormatFlag already carries cobra's own
// "json" default at this point (set by init()'s StringVar), so this test
// has to distinguish "user typed --format" from "flag left at its default"
// the same way runExportCmd does: cmd.Flags().Changed("format") — mirrors
// TestRunCheckCmdUsesSettingsDefaultViewWhenFlagNotPassed for --view.
func TestRunExportCmdUsesSettingsDefaultFormatWhenFlagNotPassed(t *testing.T) {
	dir := t.TempDir()
	invPath := filepath.Join(dir, "inv.jsonl")
	writeFile(t, invPath, `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"generic","version":"1.0","normalized":"1.0","collectedAt":"2026-01-01T00:00:00Z"}
`)
	withFakeResolver(t, fakeSource{})

	prevFrom, prevOut := exportFromFlag, exportOutputFlag
	exportFromFlag, exportOutputFlag = invPath, "-"
	t.Cleanup(func() { exportFromFlag, exportOutputFlag = prevFrom, prevOut })

	settingsPath := filepath.Join(dir, "settings.yaml")
	writeFile(t, settingsPath, "schemaVersion: 1\nexport:\n  default_format: html\n")
	withSettingsFlag(t, settingsPath)

	cmd, stdout, _ := testCmd(t)
	if err := runExportCmd(cmd, nil); err != nil {
		t.Fatalf("runExportCmd: %v", err)
	}
	if !strings.Contains(stdout.String(), "<!doctype html>") {
		t.Fatalf("expected settings.yaml's export.default_format: html to apply, got:\n%s", stdout.String())
	}
}

func TestRunExportCmdExplicitFormatFlagBeatsSettings(t *testing.T) {
	dir := t.TempDir()
	invPath := filepath.Join(dir, "inv.jsonl")
	writeFile(t, invPath, `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"generic","version":"1.0","normalized":"1.0","collectedAt":"2026-01-01T00:00:00Z"}
`)
	withFakeResolver(t, fakeSource{})
	setExportFlags(t, invPath, "json", "-")

	settingsPath := filepath.Join(dir, "settings.yaml")
	writeFile(t, settingsPath, "schemaVersion: 1\nexport:\n  default_format: html\n")
	withSettingsFlag(t, settingsPath)

	cmd, stdout, _ := testCmd(t)
	cmd.Flags().String("format", "", "")
	if err := cmd.Flags().Set("format", "json"); err != nil {
		t.Fatal(err)
	}
	if err := runExportCmd(cmd, nil); err != nil {
		t.Fatalf("runExportCmd: %v", err)
	}
	var got render.Report
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("expected explicit --format json to beat settings.yaml's default_format: html, got:\n%s", stdout.String())
	}
	if len(got.Assessments) != 1 {
		t.Fatalf("got %+v", got)
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
