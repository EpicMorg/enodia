// SPDX-License-Identifier: AGPL-3.0-or-later

package evaluate

import (
	"errors"
	"testing"
	"time"

	"github.com/EpicMorg/enodia/internal/probe"
	"github.com/EpicMorg/enodia/internal/resolver"
)

func TestEvaluateSkippedObservation(t *testing.T) {
	in := Input{Observation: probe.Observation{ID: "x", ErrorKind: "skipped"}}
	a := Evaluate(in, day("2026-01-01"), Policy{})
	if a.Reason != ReasonSkipped {
		t.Fatalf("got reason %v, want skipped", a.Reason)
	}
	if a.Patch != PatchUnknown || a.Lifecycle != LifecycleUnknown || a.Branch != BranchUnknown {
		t.Fatalf("expected all axes unknown, got %+v", a)
	}
	if a.OverallSeverity() != SeverityNone {
		t.Fatalf("got severity %v, want none — a deliberate skip is not a problem", a.OverallSeverity())
	}
}

func TestEvaluateProbeFailed(t *testing.T) {
	in := Input{Observation: probe.Observation{ID: "x", Error: "connection refused", ErrorKind: "unreachable"}}
	a := Evaluate(in, day("2026-01-01"), Policy{})
	if a.Reason != ReasonProbeFailed {
		t.Fatalf("got reason %v, want probe_failed", a.Reason)
	}
	if a.ReasonSeverity != SeverityWarn {
		t.Fatalf("got severity %v, want warn", a.ReasonSeverity)
	}
}

func TestEvaluateNoResolverConfigured(t *testing.T) {
	in := Input{
		Observation: probe.Observation{ID: "x", Version: "1.2.3", Normalized: "1.2.3"},
		Resolver:    probe.ResolverRef{}, // empty: no calendar for this product
	}
	a := Evaluate(in, day("2026-01-01"), Policy{})
	if a.Reason != ReasonNoResolver {
		t.Fatalf("got reason %v, want no_resolver", a.Reason)
	}
	if a.OverallSeverity() != SeverityNone {
		t.Fatalf("got severity %v, want none — no calendar is a normal state", a.OverallSeverity())
	}
}

func TestEvaluateResolverErrored(t *testing.T) {
	in := Input{
		Observation: probe.Observation{ID: "x", Version: "1.2.3", Normalized: "1.2.3"},
		Resolver:    probe.ResolverRef{Type: "endoflife", ID: "widget"},
		ResolveErr:  errors.New("network timeout"),
	}
	a := Evaluate(in, day("2026-01-01"), Policy{})
	if a.Reason != ReasonResolverError {
		t.Fatalf("got reason %v, want resolver_error", a.Reason)
	}
	if a.ReasonSeverity != SeverityInfo {
		t.Fatalf("got severity %v, want info", a.ReasonSeverity)
	}
}

func TestEvaluateCycleUnmatchedIsNotBuriedInPlainUnknown(t *testing.T) {
	in := Input{
		Observation: probe.Observation{ID: "x", Version: "7.0.0", Normalized: "7.0.0"},
		Resolver:    probe.ResolverRef{Type: "endoflife", ID: "jira-software"},
		Cycles: []resolver.Cycle{
			{Cycle: "10.3", Latest: "10.3.2"},
			{Cycle: "9.12", Latest: "9.12.38"},
		},
	}
	a := Evaluate(in, day("2026-01-01"), Policy{})
	if a.Reason != ReasonCycleUnmatched {
		t.Fatalf("got reason %v, want cycle_unmatched", a.Reason)
	}
	if a.ReasonSeverity != SeverityWarn {
		t.Fatalf("got severity %v, want warn — this must be visible, not silently unknown", a.ReasonSeverity)
	}
}

func TestEvaluateFullMatchAgainstJiraSoftwareLikeData(t *testing.T) {
	in := Input{
		Observation: probe.Observation{ID: "jira-prod", Version: "10.3.1-ee", Normalized: "10.3.1"},
		Resolver:    probe.ResolverRef{Type: "endoflife", ID: "jira-software"},
		Cycles: []resolver.Cycle{
			{Cycle: "10.3", Latest: "10.3.2", EOL: dateFlag("2026-12-05")},
			{Cycle: "9.12", Latest: "9.12.38", EOL: dateFlag("2025-11-29")},
		},
	}
	a := Evaluate(in, day("2026-01-01"), Policy{})

	if a.Reason != ReasonNone {
		t.Fatalf("got reason %v, want none", a.Reason)
	}
	if a.MatchedCycle != "10.3" {
		t.Fatalf("got matched cycle %q, want 10.3", a.MatchedCycle)
	}
	if a.Patch != PatchBehind {
		t.Fatalf("got patch %v, want behind (10.3.1 < 10.3.2)", a.Patch)
	}
	if a.Lifecycle != LifecycleActive {
		t.Fatalf("got lifecycle %v, want active", a.Lifecycle)
	}
	if a.Branch != BranchLatest {
		t.Fatalf("got branch %v, want latest (10.3 is the newest cycle)", a.Branch)
	}
	if a.PatchSeverity != SeverityWarn {
		t.Fatalf("got patch severity %v, want warn", a.PatchSeverity)
	}
	if a.OverallSeverity() != SeverityWarn {
		t.Fatalf("got overall severity %v, want warn", a.OverallSeverity())
	}
}

func TestEvaluateGithubFallbackSingleCycle(t *testing.T) {
	in := Input{
		Observation: probe.Observation{ID: "widget", Version: "2.8.5", Normalized: "2.8.5"},
		Resolver:    probe.ResolverRef{Type: "github", ID: "owner/repo"},
		Cycles:      []resolver.Cycle{{Cycle: "v2.9.0", Latest: "v2.9.0"}},
	}
	a := Evaluate(in, day("2026-01-01"), Policy{})

	if a.Reason != ReasonNone {
		t.Fatalf("got reason %v, want none — the single cycle must match trivially", a.Reason)
	}
	if a.Patch != PatchBehind {
		t.Fatalf("got patch %v, want behind (2.8.5 < 2.9.0)", a.Patch)
	}
	if a.Lifecycle != LifecycleUnknown {
		t.Fatalf("got lifecycle %v, want unknown — GitHub never reports eol/support", a.Lifecycle)
	}
	if a.Branch != BranchLatest {
		t.Fatalf("got branch %v, want latest (no other cycle to compare against)", a.Branch)
	}
	// Lifecycle unknown must not, on its own, produce any severity: it's an
	// expected limitation of the fallback, not a problem.
	if a.LifecycleSeverity != SeverityNone {
		t.Fatalf("got lifecycle severity %v, want none", a.LifecycleSeverity)
	}
}

func TestEvaluateFailOnEscalatesPatch(t *testing.T) {
	in := Input{
		Observation: probe.Observation{ID: "x", Version: "10.3.1", Normalized: "10.3.1"},
		Resolver:    probe.ResolverRef{Type: "endoflife", ID: "jira-software"},
		Cycles:      []resolver.Cycle{{Cycle: "10.3", Latest: "10.3.2"}},
	}
	policy := Policy{FailOn: []string{"patch:behind"}}
	a := Evaluate(in, day("2026-01-01"), policy)
	if a.PatchSeverity != SeverityFail {
		t.Fatalf("got %v, want fail", a.PatchSeverity)
	}
	if a.OverallSeverity() != SeverityFail {
		t.Fatalf("got overall %v, want fail", a.OverallSeverity())
	}
}

func TestEvaluateIsDeterministicAcrossAsOf(t *testing.T) {
	// D8: no wall-clock dependency. Two calls with the same asOf a year
	// apart in wall-clock terms must produce identical results.
	in := Input{
		Observation: probe.Observation{ID: "x", Version: "9.6.0", Normalized: "9.6.0"},
		Resolver:    probe.ResolverRef{Type: "endoflife", ID: "mysql"},
		Cycles:      []resolver.Cycle{{Cycle: "9.6", Latest: "9.6.1", EOL: dateFlag("2026-04-21")}},
	}
	asOf := day("2026-01-01")
	a1 := Evaluate(in, asOf, Policy{})
	time.Sleep(2 * time.Millisecond) // wall clock moves; asOf does not
	a2 := Evaluate(in, asOf, Policy{})

	// EOLDate/SupportEnds are separately allocated *time.Time per call, so
	// compare the rest of the struct plus dereferenced dates rather than
	// the structs directly (which would compare pointer identity).
	a1NoDates, a2NoDates := a1, a2
	a1NoDates.EOLDate, a1NoDates.SupportEnds = nil, nil
	a2NoDates.EOLDate, a2NoDates.SupportEnds = nil, nil
	if a1NoDates != a2NoDates {
		t.Fatalf("Evaluate was not deterministic for the same asOf:\n%+v\n%+v", a1, a2)
	}
	if (a1.EOLDate == nil) != (a2.EOLDate == nil) || (a1.EOLDate != nil && !a1.EOLDate.Equal(*a2.EOLDate)) {
		t.Fatalf("EOLDate differed: %v vs %v", a1.EOLDate, a2.EOLDate)
	}
}

func TestEvaluateNormalizedFallsBackToCleaningRawVersion(t *testing.T) {
	// Defensive: an Observation from an older writer that never set
	// Normalized must still evaluate correctly.
	in := Input{
		Observation: probe.Observation{ID: "x", Version: "v10.3.2", Normalized: ""},
		Resolver:    probe.ResolverRef{Type: "endoflife", ID: "jira-software"},
		Cycles:      []resolver.Cycle{{Cycle: "10.3", Latest: "10.3.2"}},
	}
	a := Evaluate(in, day("2026-01-01"), Policy{})
	if a.Patch != PatchCurrent {
		t.Fatalf("got %v, want current", a.Patch)
	}
}
