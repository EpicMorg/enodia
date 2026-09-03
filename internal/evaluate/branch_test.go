// SPDX-License-Identifier: AGPL-3.0-or-later

package evaluate

import (
	"testing"

	"github.com/EpicMorg/enodia/internal/resolver"
)

func TestEvaluateBranchLatestWhenNoOtherCycles(t *testing.T) {
	cycles := []resolver.Cycle{{Cycle: "10.3"}}
	if got := evaluateBranch("10.3", cycles); got != BranchLatest {
		t.Fatalf("got %v, want latest", got)
	}
}

func TestEvaluateBranchLatestIgnoresOlderCycles(t *testing.T) {
	cycles := []resolver.Cycle{{Cycle: "10.3"}, {Cycle: "9.12"}, {Cycle: "9.11"}}
	if got := evaluateBranch("10.3", cycles); got != BranchLatest {
		t.Fatalf("got %v, want latest (10.3 is already the newest)", got)
	}
}

func TestEvaluateBranchNewerWhenNonLTSCycleIsNewer(t *testing.T) {
	cycles := []resolver.Cycle{{Cycle: "9.12"}, {Cycle: "10.3"}}
	if got := evaluateBranch("9.12", cycles); got != BranchNewer {
		t.Fatalf("got %v, want newer", got)
	}
}

func TestEvaluateBranchNewerLTSWhenNewerCycleIsLTS(t *testing.T) {
	cycles := []resolver.Cycle{
		{Cycle: "9.12", LTS: boolFlag(true)},
		{Cycle: "10.3", LTS: boolFlag(true)},
	}
	if got := evaluateBranch("9.12", cycles); got != BranchNewerLTS {
		t.Fatalf("got %v, want newer_lts", got)
	}
}

func TestEvaluateBranchNewerLTSViaDateForm(t *testing.T) {
	// nodejs reports lts as a date rather than a bare bool; Bool is still
	// true in that case (see Flag.UnmarshalJSON), so this must count too.
	cycles := []resolver.Cycle{
		{Cycle: "24"},
		{Cycle: "26", LTS: dateFlag("2026-10-28")},
	}
	if got := evaluateBranch("24", cycles); got != BranchNewerLTS {
		t.Fatalf("got %v, want newer_lts", got)
	}
}

func TestEvaluateBranchNewerLTSTakesPriorityOverPlainNewer(t *testing.T) {
	cycles := []resolver.Cycle{
		{Cycle: "10.0"},                      // matched
		{Cycle: "10.1"},                      // newer, not LTS
		{Cycle: "11.0", LTS: boolFlag(true)}, // newer, LTS
	}
	if got := evaluateBranch("10.0", cycles); got != BranchNewerLTS {
		t.Fatalf("got %v, want newer_lts even though a plain-newer cycle also exists", got)
	}
}

func TestEvaluateBranchIgnoresEqualCycle(t *testing.T) {
	cycles := []resolver.Cycle{{Cycle: "10.3"}, {Cycle: "10.3"}}
	if got := evaluateBranch("10.3", cycles); got != BranchLatest {
		t.Fatalf("got %v, want latest (a duplicate/equal entry is not newer)", got)
	}
}
