// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/EpicMorg/enodia/internal/resolver"
)

// withFakeResolver swaps buildResolver for one wired to src for the
// duration of the test, so check/export never touch the real network.
func withFakeResolver(t *testing.T, src resolver.Source) {
	t.Helper()
	prev := buildResolver
	buildResolver = func(*cobra.Command) *resolver.Resolver {
		return &resolver.Resolver{Sources: map[string]resolver.Source{"endoflife": src}}
	}
	t.Cleanup(func() { buildResolver = prev })
}

func TestRunCheckCmdFromInventoryPlainPasses(t *testing.T) {
	dir := t.TempDir()
	invPath := filepath.Join(dir, "inv.jsonl")
	writeFile(t, invPath, `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"generic","version":"1.0","normalized":"1.0","collectedAt":"2026-01-01T00:00:00Z"}
`)
	withFakeResolver(t, fakeSource{})

	prevFrom := checkFromFlag
	checkFromFlag = invPath
	t.Cleanup(func() { checkFromFlag = prevFrom })

	cmd, stdout, _ := testCmd(t)
	err := runCheckCmd(cmd, nil)
	if err != nil {
		t.Fatalf("expected no error (generic has no resolver, so no findings), got %v", err)
	}
	if !strings.Contains(stdout.String(), "generic") {
		t.Fatalf("expected the report to mention the target, got %q", stdout.String())
	}
}

func TestRunCheckCmdExitsThreeOnWarnFindings(t *testing.T) {
	dir := t.TempDir()
	invPath := filepath.Join(dir, "inv.jsonl")
	writeFile(t, invPath, `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"jira","version":"10.3.1","normalized":"10.3.1","collectedAt":"2026-01-01T00:00:00Z"}
`)
	withFakeResolver(t, fakeSource{cycles: []resolver.Cycle{{Cycle: "10.3", Latest: "10.3.2"}}})

	prevFrom := checkFromFlag
	checkFromFlag = invPath
	t.Cleanup(func() { checkFromFlag = prevFrom })

	cmd, _, _ := testCmd(t)
	err := runCheckCmd(cmd, nil)
	if err == nil {
		t.Fatal("expected an ExitError for a behind-patch finding")
	}
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 3 {
		t.Fatalf("got %v, want ExitError{Code:3}", err)
	}
}

// settings.yaml's render.default_view applies only when --view was not
// passed on the command line; checkViewFlag already carries cobra's own
// "compact" default at this point (set by init()'s StringVar), so this
// test has to distinguish "user typed --view" from "flag left at its
// default" the same way runCheckCmd does: cmd.Flags().Changed("view").
func TestRunCheckCmdUsesSettingsDefaultViewWhenFlagNotPassed(t *testing.T) {
	dir := t.TempDir()
	invPath := filepath.Join(dir, "inv.jsonl")
	writeFile(t, invPath, `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"generic","version":"1.0","normalized":"1.0","collectedAt":"2026-01-01T00:00:00Z"}
`)
	withFakeResolver(t, fakeSource{})

	prevFrom := checkFromFlag
	checkFromFlag = invPath
	t.Cleanup(func() { checkFromFlag = prevFrom })

	settingsPath := filepath.Join(dir, "settings.yaml")
	writeFile(t, settingsPath, "schemaVersion: 1\nrender:\n  default_view: fleet\n")
	withSettingsFlag(t, settingsPath)

	cmd, stdout, _ := testCmd(t)
	if err := runCheckCmd(cmd, nil); err != nil {
		t.Fatalf("runCheckCmd: %v", err)
	}
	// The fleet view's header is PRODUCT/VERSION/STATUS/COUNT/INSTANCES;
	// the compact view's is ID/PRODUCT/PATCH/.... COUNT only appears in
	// fleet's header.
	if !strings.Contains(stdout.String(), "COUNT") {
		t.Fatalf("expected settings.yaml's default_view: fleet to apply, got:\n%s", stdout.String())
	}
}

func TestRunCheckCmdExplicitViewFlagBeatsSettings(t *testing.T) {
	dir := t.TempDir()
	invPath := filepath.Join(dir, "inv.jsonl")
	writeFile(t, invPath, `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"generic","version":"1.0","normalized":"1.0","collectedAt":"2026-01-01T00:00:00Z"}
`)
	withFakeResolver(t, fakeSource{})

	prevFrom := checkFromFlag
	checkFromFlag = invPath
	t.Cleanup(func() { checkFromFlag = prevFrom })

	settingsPath := filepath.Join(dir, "settings.yaml")
	writeFile(t, settingsPath, "schemaVersion: 1\nrender:\n  default_view: fleet\n")
	withSettingsFlag(t, settingsPath)

	prevView := checkViewFlag
	checkViewFlag = "lifecycle"
	t.Cleanup(func() { checkViewFlag = prevView })

	cmd, stdout, _ := testCmd(t)
	cmd.Flags().String("view", "", "")
	if err := cmd.Flags().Set("view", "lifecycle"); err != nil {
		t.Fatal(err)
	}
	if err := runCheckCmd(cmd, nil); err != nil {
		t.Fatalf("runCheckCmd: %v", err)
	}
	if !strings.Contains(stdout.String(), "SUPPORT-ENDS") {
		t.Fatalf("expected the explicit --view=lifecycle to win over settings.yaml, got:\n%s", stdout.String())
	}
}

func TestRunCheckCmdMissingInventoryIsInternalError(t *testing.T) {
	prevFrom := checkFromFlag
	checkFromFlag = filepath.Join(t.TempDir(), "nope.jsonl")
	t.Cleanup(func() { checkFromFlag = prevFrom })

	cmd, _, _ := testCmd(t)
	err := runCheckCmd(cmd, nil)
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 1 {
		t.Fatalf("got %v, want ExitError{Code:1}", err)
	}
}
