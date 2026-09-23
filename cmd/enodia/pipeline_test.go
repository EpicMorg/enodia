// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/EpicMorg/enodia/internal/cve"
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

// fakeMultiSource, unlike fakeSource, answers differently per ref.ID — for
// tests that need to prove which of several possible calendars actually
// got queried, not just that some fixed answer came back regardless.
type fakeMultiSource map[string]fakeSource

func (s fakeMultiSource) Fetch(ctx context.Context, ref probe.ResolverRef) ([]resolver.Cycle, error) {
	return s[ref.ID].Fetch(ctx, ref)
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
	got := assess(cmd.Context(), inv, evaluate.Policy{}, res, nil)
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
	got := assess(cmd.Context(), inv, evaluate.Policy{}, res, nil)
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Reason != evaluate.ReasonNone || got[0].Patch != evaluate.PatchBehind {
		t.Fatalf("got %+v, want a real cycle match against the fake source", got[0])
	}
}

// A product like sonarqube can only tell which of two lifecycle calendars
// applies after seeing its own version reply; Observation.Resolver is how
// it overrides its product's static Meta().DefaultResolver for that one
// instance. This uses "jira" as the Product (any registered probe works,
// since assess only reads Meta().DefaultResolver as the pre-override
// fallback) with two distinct fake sources to prove the override, not the
// static default, decides which one gets queried.
func TestAssessObservationResolverOverridesProductDefault(t *testing.T) {
	inv := &inventory.File{
		Header: inventory.Header{CollectedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		Observations: []probe.Observation{
			{
				ID: "x", Product: "jira", Version: "26.9.0.129388", Normalized: "26.9.0.129388",
				Resolver: &probe.ResolverRef{Type: "endoflife", ID: "sonarqube-community"},
			},
		},
	}
	cmd, _, _ := testCmd(t)
	res := &resolver.Resolver{
		Sources: map[string]resolver.Source{
			// jira's own static default would resolve here if the override
			// were ignored, and 26.9 would show as PatchUnknown against it.
			"endoflife": fakeMultiSource{
				"jira":                {cycles: []resolver.Cycle{{Cycle: "10.3", Latest: "10.3.2"}}},
				"sonarqube-community": {cycles: []resolver.Cycle{{Cycle: "26.9", Latest: "26.9.0.129388"}}},
			},
		},
	}
	got := assess(cmd.Context(), inv, evaluate.Policy{}, res, nil)
	if len(got) != 1 || got[0].Reason != evaluate.ReasonNone || got[0].Patch != evaluate.PatchCurrent {
		t.Fatalf("got %+v, want a clean match against sonarqube-community, not jira's own default", got)
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
	got := assess(cmd.Context(), inv, evaluate.Policy{}, res, nil)
	if len(got) != 1 || got[0].Reason != evaluate.ReasonResolverError {
		t.Fatalf("got %+v", got)
	}
}

// TestAssessLooksUpCVEFindings proves assess wires a non-nil cve.Index
// through to Evaluate: a Confluence observation vulnerable per the real
// BDU:2023-06364 entry (see internal/cve/testdata/sample.xml, the exact
// CVE-2023-22515 example D18 used to show OSV.dev's gap) must surface it
// in the resulting Assessment, with no resolver configured at all — CVE
// lookup is independent of lifecycle resolution.
func TestAssessLooksUpCVEFindings(t *testing.T) {
	idx, err := cve.LoadBDU(filepath.Join("..", "..", "internal", "cve", "testdata", "sample.xml"))
	if err != nil {
		t.Fatalf("LoadBDU: %v", err)
	}

	inv := &inventory.File{
		Header: inventory.Header{CollectedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		Observations: []probe.Observation{
			{ID: "x", Product: "confluence", Version: "8.1.0", Normalized: "8.1.0"},
		},
	}
	cmd, _, _ := testCmd(t)
	got := assess(cmd.Context(), inv, evaluate.Policy{}, &resolver.Resolver{}, idx)
	if len(got) != 1 || len(got[0].CVEs) == 0 {
		t.Fatalf("got %+v, want at least one CVE finding for a vulnerable Confluence version", got)
	}
}

// TestAssessNilCVEIndexLeavesCVEsEmpty proves the opt-in nil case (no
// cve.bdu.path configured) behaves like ReasonNoResolver's "fact simply
// not available" shape, not a crash — cveIndex.Lookup must be nil-safe.
func TestAssessNilCVEIndexLeavesCVEsEmpty(t *testing.T) {
	inv := &inventory.File{
		Header: inventory.Header{CollectedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		Observations: []probe.Observation{
			{ID: "x", Product: "confluence", Version: "8.1.0", Normalized: "8.1.0"},
		},
	}
	cmd, _, _ := testCmd(t)
	got := assess(cmd.Context(), inv, evaluate.Policy{}, &resolver.Resolver{}, nil)
	if len(got) != 1 || len(got[0].CVEs) != 0 {
		t.Fatalf("got %+v, want no CVEs with a nil index", got)
	}
}

// TestLoadCVEIndexMergesBDUAndNVD proves loadCVEIndex wires both
// cve.bdu.path and cve.nvd.path, when both are configured, into one
// merged Index rather than one silently overriding the other.
func TestLoadCVEIndexMergesBDUAndNVD(t *testing.T) {
	bduPath, err := filepath.Abs(filepath.Join("..", "..", "internal", "cve", "testdata", "sample.xml"))
	if err != nil {
		t.Fatal(err)
	}
	nvdPath, err := filepath.Abs(filepath.Join("..", "..", "internal", "cve", "testdata", "sample_nvd.json"))
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "enodia.yaml")
	writeFile(t, path, `
schemaVersion: 1
targets: []
cve:
  bdu:
    path: `+bduPath+`
  nvd:
    path: `+nvdPath+`
`)
	withConfigFlag(t, path)

	cmd, _, _ := testCmd(t)
	idx, err := loadCVEIndex(cmd)
	if err != nil {
		t.Fatalf("loadCVEIndex: %v", err)
	}
	got := idx.Lookup("confluence", "8.3.0", "")
	sources := map[string]int{}
	for _, f := range got {
		sources[f.Source]++
	}
	if sources["bdu"] == 0 || sources["nvd"] == 0 {
		t.Fatalf("got sources %+v, want findings from both bdu and nvd", sources)
	}
}

// The cve block must come from whichever config the run actually uses,
// not only an explicit --config: D30 first required the flag, which
// silently dropped CVEs for every $ENODIA_CONFIG or auto-located setup
// (D34). $ENODIA_CONFIG outranks the default search paths, so this is
// hermetic regardless of what the machine has in /etc/enodia.
func TestLoadCVEIndexHonorsENODIA_CONFIG(t *testing.T) {
	nvdPath, err := filepath.Abs(filepath.Join("..", "..", "internal", "cve", "testdata", "nvd_gitlab.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "enodia.yaml")
	writeFile(t, path, `
schemaVersion: 1
targets: []
cve:
  nvd:
    path: `+nvdPath+`
`)
	withConfigFlag(t, "")
	t.Setenv("ENODIA_CONFIG", path)

	cmd, _, _ := testCmd(t)
	idx, err := loadCVEIndex(cmd)
	if err != nil {
		t.Fatalf("loadCVEIndex: %v", err)
	}
	if got := idx.Lookup("gitlab", "19.2.2", "enterprise"); len(got) == 0 {
		t.Fatal("got no findings: the cve block of $ENODIA_CONFIG was ignored")
	}
}

// A config without a cve block means no CVE correlation, not an error.
func TestLoadCVEIndexConfigWithoutCVEBlockIsNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enodia.yaml")
	writeFile(t, path, "schemaVersion: 1\ntargets: []\n")
	withConfigFlag(t, path)

	cmd, _, _ := testCmd(t)
	idx, err := loadCVEIndex(cmd)
	if err != nil {
		t.Fatalf("loadCVEIndex: %v", err)
	}
	if idx != nil {
		t.Fatalf("got %+v, want nil with no cve block", idx)
	}
}

// An explicit --config that doesn't exist is still an error — only "no
// config located anywhere" (a valid state for check --from) is not.
func TestLoadCVEIndexMissingExplicitConfigErrors(t *testing.T) {
	withConfigFlag(t, filepath.Join(t.TempDir(), "nope.yaml"))
	cmd, _, _ := testCmd(t)
	if _, err := loadCVEIndex(cmd); err == nil {
		t.Fatal("expected an error for a missing explicit --config")
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

// assess must route an observation through cve.Subject: a GitLab CE
// instance (the probe's own Extra["enterprise"] = "false") sees only the
// findings that apply to CE, not the EE-only ones in the same real data.
func TestAssessGitLabEditionFiltersCVEs(t *testing.T) {
	idx, err := cve.LoadNVD(filepath.Join("..", "..", "internal", "cve", "testdata", "nvd_gitlab.json"))
	if err != nil {
		t.Fatalf("LoadNVD: %v", err)
	}
	obs := func(id, enterprise string) probe.Observation {
		return probe.Observation{ID: id, Product: "gitlab", Version: "19.2.2", Normalized: "19.2.2",
			Extra: map[string]string{"enterprise": enterprise}}
	}
	inv := &inventory.File{
		Header:       inventory.Header{CollectedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		Observations: []probe.Observation{obs("ce", "false"), obs("ee", "true")},
	}
	cmd, _, _ := testCmd(t)
	got := assess(cmd.Context(), inv, evaluate.Policy{}, &resolver.Resolver{}, idx)
	if len(got) != 2 {
		t.Fatalf("got %d assessments, want 2", len(got))
	}
	for _, f := range got[0].CVEs {
		if f.Edition == "enterprise" {
			t.Fatalf("CE instance got an enterprise-only finding: %s", f.AdvisoryID)
		}
	}
	if len(got[0].CVEs) >= len(got[1].CVEs) {
		t.Fatalf("CE got %d findings, EE got %d — EE should see strictly more", len(got[0].CVEs), len(got[1].CVEs))
	}
}
