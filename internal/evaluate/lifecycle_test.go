// SPDX-License-Identifier: AGPL-3.0-or-later

package evaluate

import (
	"testing"

	"github.com/EpicMorg/enodia/internal/resolver"
)

func TestIsPastNilFlag(t *testing.T) {
	if isPast(nil, day("2026-01-01")) {
		t.Fatal("nil flag must never be past")
	}
}

func TestIsPastBareBoolNeverCountsAsPast(t *testing.T) {
	// Confirmed against the live API: redis reports "support": true on its
	// newest, most-active cycle. A bare true must not mean "already over".
	if isPast(boolFlag(true), day("2026-01-01")) {
		t.Fatal("a bare true with no date must not count as past")
	}
	if isPast(boolFlag(false), day("2026-01-01")) {
		t.Fatal("a bare false must not count as past")
	}
}

func TestIsPastDateBoundary(t *testing.T) {
	f := dateFlag("2026-06-01")
	if isPast(f, day("2026-05-31")) {
		t.Fatal("a day before the date must not be past")
	}
	if !isPast(f, day("2026-06-01")) {
		t.Fatal("the exact date itself must count as past")
	}
	if !isPast(f, day("2026-06-02")) {
		t.Fatal("a day after the date must be past")
	}
}

func TestFlagDate(t *testing.T) {
	if got := flagDate(nil); got != nil {
		t.Fatalf("got %v, want nil", got)
	}
	if got := flagDate(boolFlag(true)); got != nil {
		t.Fatalf("got %v, want nil for a bare bool", got)
	}
	f := dateFlag("2026-06-01")
	got := flagDate(f)
	if got == nil || !got.Equal(day("2026-06-01")) {
		t.Fatalf("got %v, want 2026-06-01", got)
	}
}

func TestEvaluateLifecycleNoEOLDataIsUnknown(t *testing.T) {
	c := resolver.Cycle{Cycle: "1.0"} // EOL nil, e.g. the GitHub fallback
	l, eol, support := evaluateLifecycle(c, day("2026-01-01"))
	if l != LifecycleUnknown {
		t.Fatalf("got %v, want Unknown", l)
	}
	if eol != nil || support != nil {
		t.Fatalf("got eol=%v support=%v, want both nil", eol, support)
	}
}

func TestEvaluateLifecycleActiveWhenEOLIsFalse(t *testing.T) {
	c := resolver.Cycle{Cycle: "8.10", EOL: boolFlag(false), Support: boolFlag(true)}
	l, _, _ := evaluateLifecycle(c, day("2026-01-01"))
	if l != LifecycleActive {
		t.Fatalf("got %v, want Active (matches redis's eol:false, support:true on its newest cycle)", l)
	}
}

func TestEvaluateLifecycleActiveBeforeEOLDate(t *testing.T) {
	c := resolver.Cycle{Cycle: "11.3", EOL: dateFlag("2027-12-03")}
	l, eol, _ := evaluateLifecycle(c, day("2026-01-01"))
	if l != LifecycleActive {
		t.Fatalf("got %v, want Active", l)
	}
	if eol == nil || !eol.Equal(day("2027-12-03")) {
		t.Fatalf("got eol=%v", eol)
	}
}

func TestEvaluateLifecycleEOLOnAndAfterDate(t *testing.T) {
	c := resolver.Cycle{Cycle: "9.6", EOL: dateFlag("2026-04-21")}
	if l, _, _ := evaluateLifecycle(c, day("2026-04-21")); l != LifecycleEOL {
		t.Fatalf("got %v, want EOL on the exact date", l)
	}
	if l, _, _ := evaluateLifecycle(c, day("2026-05-01")); l != LifecycleEOL {
		t.Fatalf("got %v, want EOL after the date", l)
	}
}

func TestEvaluateLifecycleSecurityBetweenSupportAndEOL(t *testing.T) {
	c := resolver.Cycle{
		Cycle:   "25.10",
		EOL:     dateFlag("2026-07-01"),
		Support: dateFlag("2026-01-01"),
	}
	l, eol, support := evaluateLifecycle(c, day("2026-03-01"))
	if l != LifecycleSecurity {
		t.Fatalf("got %v, want Security (past support end, before eol)", l)
	}
	if eol == nil || support == nil {
		t.Fatalf("expected both dates populated, got eol=%v support=%v", eol, support)
	}
}

func TestEvaluateLifecycleEOLTakesPriorityOverSupport(t *testing.T) {
	// mysql-style: support and eol land on the same day. Once reached,
	// that's EOL outright, not a zero-width security window.
	c := resolver.Cycle{Cycle: "9.6", EOL: dateFlag("2026-04-21"), Support: dateFlag("2026-04-21")}
	l, _, _ := evaluateLifecycle(c, day("2026-04-21"))
	if l != LifecycleEOL {
		t.Fatalf("got %v, want EOL", l)
	}
}

func TestEvaluateLifecycleActiveWithNoSupportField(t *testing.T) {
	// jira-software-style: eol is a future date, support isn't reported.
	c := resolver.Cycle{Cycle: "11.3", EOL: dateFlag("2027-12-03")}
	l, _, support := evaluateLifecycle(c, day("2026-01-01"))
	if l != LifecycleActive {
		t.Fatalf("got %v, want Active", l)
	}
	if support != nil {
		t.Fatalf("got %v, want nil (support was never reported)", support)
	}
}
