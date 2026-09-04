// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/EpicMorg/enodia/internal/evaluate"
	"github.com/EpicMorg/enodia/internal/inventory"
	"github.com/EpicMorg/enodia/internal/probe"
	"github.com/EpicMorg/enodia/internal/resolver"
)

const jiraManifest = `<?xml version="1.0"?><manifest><typeId>jira</typeId><version>10.3.2</version></manifest>`

type fakeSource struct {
	cycles []resolver.Cycle
	err    error
}

func (s fakeSource) Fetch(context.Context, probe.ResolverRef) ([]resolver.Cycle, error) {
	return s.cycles, s.err
}

func TestCollectObservationsBuildsFromConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(jiraManifest))
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "enodia.yaml")
	writeFile(t, path, `
schemaVersion: 1
targets:
  - id: jira-1
    product: jira
    address: `+srv.URL+`
    timeout: 5s
`)
	withConfigFlag(t, path)

	cmd, _, _ := testCmd(t)
	cfg, observations, err := collectObservations(cmd.Context(), cmd)
	if err != nil {
		t.Fatalf("collectObservations: %v", err)
	}
	if cfg == nil || len(cfg.Targets) != 1 {
		t.Fatalf("got cfg %+v", cfg)
	}
	if len(observations) != 1 || observations[0].Version != "10.3.2" {
		t.Fatalf("got %+v", observations)
	}
}

func TestCollectObservationsPropagatesConfigError(t *testing.T) {
	withConfigFlag(t, filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	cmd, _, _ := testCmd(t)
	if _, _, err := collectObservations(cmd.Context(), cmd); err == nil {
		t.Fatal("expected an error for a missing config file")
	}
}

func TestLoadInventoryFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inv.jsonl")
	writeFile(t, path, `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"jira","version":"10.3.2","normalized":"10.3.2","collectedAt":"2026-01-01T00:00:00Z"}
`)
	cmd, _, _ := testCmd(t)
	inv, err := loadInventory(cmd.Context(), cmd, path)
	if err != nil {
		t.Fatalf("loadInventory: %v", err)
	}
	if len(inv.Observations) != 1 || inv.Observations[0].ID != "x" {
		t.Fatalf("got %+v", inv.Observations)
	}
}

func TestLoadInventoryFromFileMissingErrors(t *testing.T) {
	cmd, _, _ := testCmd(t)
	if _, err := loadInventory(cmd.Context(), cmd, filepath.Join(t.TempDir(), "nope.jsonl")); err == nil {
		t.Fatal("expected an error for a missing --from file")
	}
}

func TestLoadInventoryWithoutFromCollects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(jiraManifest))
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "enodia.yaml")
	writeFile(t, path, `
schemaVersion: 1
targets:
  - id: jira-1
    product: jira
    address: `+srv.URL+`
    timeout: 5s
`)
	withConfigFlag(t, path)

	cmd, _, _ := testCmd(t)
	inv, err := loadInventory(cmd.Context(), cmd, "")
	if err != nil {
		t.Fatalf("loadInventory: %v", err)
	}
	if len(inv.Observations) != 1 || inv.Observations[0].Version != "10.3.2" {
		t.Fatalf("got %+v", inv.Observations)
	}
	if inv.Header.CollectedAt.IsZero() {
		t.Fatal("expected a non-zero CollectedAt")
	}
}

func TestAssessNoResolverForProductWithoutOne(t *testing.T) {
	inv := &inventory.File{
		Header:       inventory.Header{CollectedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		Observations: []probe.Observation{{ID: "x", Product: "generic", Version: "1.0", Normalized: "1.0"}},
	}
	cmd, _, _ := testCmd(t)
	res := &resolver.Resolver{}
	got := assess(cmd.Context(), inv, evaluate.Policy{}, res)
	if len(got) != 1 || got[0].Reason != evaluate.ReasonNoResolver {
		t.Fatalf("got %+v", got)
	}
}

func TestAssessUsesResolverForProductWithOne(t *testing.T) {
	inv := &inventory.File{
		Header: inventory.Header{CollectedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		Observations: []probe.Observation{
			{ID: "x", Product: "jira", Version: "10.3.1", Normalized: "10.3.1"},
		},
	}
	cmd, _, _ := testCmd(t)
	res := &resolver.Resolver{
		Sources: map[string]resolver.Source{
			"endoflife": fakeSource{cycles: []resolver.Cycle{{Cycle: "10.3", Latest: "10.3.2"}}},
		},
	}
	got := assess(cmd.Context(), inv, evaluate.Policy{}, res)
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Reason != evaluate.ReasonNone || got[0].Patch != evaluate.PatchBehind {
		t.Fatalf("got %+v, want a real cycle match against the fake source", got[0])
	}
}

func TestAssessResolverErrorBecomesReason(t *testing.T) {
	inv := &inventory.File{
		Header: inventory.Header{CollectedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		Observations: []probe.Observation{
			{ID: "x", Product: "jira", Version: "10.3.1", Normalized: "10.3.1"},
		},
	}
	cmd, _, _ := testCmd(t)
	res := &resolver.Resolver{
		Sources: map[string]resolver.Source{
			"endoflife": fakeSource{err: resolver.ErrUnreachable},
		},
	}
	got := assess(cmd.Context(), inv, evaluate.Policy{}, res)
	if len(got) != 1 || got[0].Reason != evaluate.ReasonResolverError {
		t.Fatalf("got %+v", got)
	}
}

func TestWorstSeverityIsTheMax(t *testing.T) {
	assessments := []evaluate.Assessment{
		{PatchSeverity: evaluate.SeverityNone, LifecycleSeverity: evaluate.SeverityNone, BranchSeverity: evaluate.SeverityNone, ReasonSeverity: evaluate.SeverityNone},
		{LifecycleSeverity: evaluate.SeverityWarn},
		{PatchSeverity: evaluate.SeverityInfo},
	}
	if got := worstSeverity(assessments); got != evaluate.SeverityWarn {
		t.Fatalf("got %v, want warn", got)
	}
}

func TestWorstSeverityEmptyIsNone(t *testing.T) {
	if got := worstSeverity(nil); got != evaluate.SeverityNone {
		t.Fatalf("got %v, want none", got)
	}
}

func TestSeverityExitCode(t *testing.T) {
	cases := []struct {
		sev  evaluate.Severity
		want int
	}{
		{evaluate.SeverityNone, 0},
		{evaluate.SeverityInfo, 3},
		{evaluate.SeverityWarn, 3},
		{evaluate.SeverityFail, 4},
	}
	for _, c := range cases {
		if got := severityExitCode(c.sev); got != c.want {
			t.Errorf("severityExitCode(%v) = %d, want %d", c.sev, got, c.want)
		}
	}
}

func TestNewLiveResolverWarnsWhenCacheDirUnavailable(t *testing.T) {
	// Sanity: newLiveResolver must not panic and must still return a usable
	// resolver even if DefaultCacheDir failed (it warns instead of failing).
	cmd, _, _ := testCmd(t)
	res := newLiveResolver(cmd)
	if res == nil || res.Sources["endoflife"] == nil || res.Sources["github"] == nil {
		t.Fatalf("got %+v, want both sources wired", res)
	}
}
