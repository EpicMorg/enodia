// SPDX-License-Identifier: AGPL-3.0-or-later

package evaluate

import (
	"testing"
	"time"
)

func ptr(t time.Time) *time.Time { return &t }

func TestPolicyEscalateMatchesListedPair(t *testing.T) {
	p := Policy{FailOn: []string{"patch:behind"}}
	if got := p.escalate("patch", "behind", SeverityWarn); got != SeverityFail {
		t.Fatalf("got %v, want fail", got)
	}
}

func TestPolicyEscalateLeavesUnlistedPairAlone(t *testing.T) {
	p := Policy{FailOn: []string{"patch:behind"}}
	if got := p.escalate("lifecycle", "security", SeverityWarn); got != SeverityWarn {
		t.Fatalf("got %v, want the base severity unchanged", got)
	}
}

func TestDefaultSeverityTables(t *testing.T) {
	cases := []struct {
		got, want Severity
	}{
		{defaultPatchSeverity(PatchCurrent), SeverityNone},
		{defaultPatchSeverity(PatchAhead), SeverityNone},
		{defaultPatchSeverity(PatchBehind), SeverityWarn},
		{defaultPatchSeverity(PatchUnknown), SeverityNone},

		{defaultLifecycleSeverity(LifecycleActive), SeverityNone},
		{defaultLifecycleSeverity(LifecycleSecurity), SeverityWarn},
		{defaultLifecycleSeverity(LifecycleEOL), SeverityFail},
		{defaultLifecycleSeverity(LifecycleUnknown), SeverityNone},

		{defaultBranchSeverity(BranchLatest), SeverityNone},
		{defaultBranchSeverity(BranchNewer), SeverityInfo},
		{defaultBranchSeverity(BranchNewerLTS), SeverityWarn},
		{defaultBranchSeverity(BranchUnknown), SeverityNone},

		{defaultReasonSeverity(ReasonNone), SeverityNone},
		{defaultReasonSeverity(ReasonSkipped), SeverityNone},
		{defaultReasonSeverity(ReasonNoResolver), SeverityNone},
		{defaultReasonSeverity(ReasonResolverError), SeverityInfo},
		{defaultReasonSeverity(ReasonProbeFailed), SeverityWarn},
		{defaultReasonSeverity(ReasonCycleUnmatched), SeverityWarn},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestApplySeveritiesWarnDaysBeforeEOL(t *testing.T) {
	a := &Assessment{Lifecycle: LifecycleActive, EOLDate: ptr(day("2026-06-01"))}
	a.applySeverities(Policy{WarnDays: 30}, day("2026-05-15"))
	if a.LifecycleSeverity != SeverityWarn {
		t.Fatalf("got %v, want warn (16 days out, inside a 30-day window)", a.LifecycleSeverity)
	}
}

func TestApplySeveritiesWarnDaysNotYetInWindow(t *testing.T) {
	a := &Assessment{Lifecycle: LifecycleActive, EOLDate: ptr(day("2026-06-01"))}
	a.applySeverities(Policy{WarnDays: 30}, day("2026-01-01"))
	if a.LifecycleSeverity != SeverityNone {
		t.Fatalf("got %v, want none (far outside the warn window)", a.LifecycleSeverity)
	}
}

func TestApplySeveritiesWarnDaysDoesNotDowngradeExistingEOL(t *testing.T) {
	a := &Assessment{Lifecycle: LifecycleEOL, EOLDate: ptr(day("2026-01-01"))}
	a.applySeverities(Policy{WarnDays: 30}, day("2026-06-01"))
	if a.LifecycleSeverity != SeverityFail {
		t.Fatalf("got %v, want fail (already eol; WarnDays must not soften that)", a.LifecycleSeverity)
	}
}

func TestApplySeveritiesWarnDaysBeforeSupportEnd(t *testing.T) {
	a := &Assessment{Lifecycle: LifecycleActive, SupportEnds: ptr(day("2026-06-01"))}
	a.applySeverities(Policy{WarnDays: 30}, day("2026-05-20"))
	if a.LifecycleSeverity != SeverityWarn {
		t.Fatalf("got %v, want warn", a.LifecycleSeverity)
	}
}

func TestApplySeveritiesFailOnEscalatesReason(t *testing.T) {
	a := &Assessment{Reason: ReasonCycleUnmatched}
	a.applySeverities(Policy{FailOn: []string{"reason:cycle_unmatched"}}, day("2026-01-01"))
	if a.ReasonSeverity != SeverityFail {
		t.Fatalf("got %v, want fail", a.ReasonSeverity)
	}
}

func TestOverallSeverityIsTheMax(t *testing.T) {
	a := Assessment{
		PatchSeverity:     SeverityNone,
		LifecycleSeverity: SeverityWarn,
		BranchSeverity:    SeverityInfo,
		ReasonSeverity:    SeverityNone,
	}
	if got := a.OverallSeverity(); got != SeverityWarn {
		t.Fatalf("got %v, want warn", got)
	}
}

func TestMaxPicksMoreSevere(t *testing.T) {
	if got := Max(SeverityNone, SeverityWarn); got != SeverityWarn {
		t.Fatalf("got %v, want warn", got)
	}
	if got := Max(SeverityFail, SeverityWarn); got != SeverityFail {
		t.Fatalf("got %v, want fail", got)
	}
	if got := Max(SeverityInfo, SeverityInfo); got != SeverityInfo {
		t.Fatalf("got %v, want info", got)
	}
}
