// SPDX-License-Identifier: AGPL-3.0-or-later

package evaluate

import (
	"testing"

	"github.com/EpicMorg/enodia/internal/resolver"
)

func TestDefaultCycleMatcherPicksMostSpecificBranch(t *testing.T) {
	cycles := []resolver.Cycle{
		{Cycle: "10", Latest: "10.9.9"},
		{Cycle: "10.3", Latest: "10.3.2"},
	}
	got, ok := defaultCycleMatcher("10.3.1", cycles)
	if !ok {
		t.Fatal("expected a match")
	}
	if got.Cycle != "10.3" {
		t.Fatalf("got %q, want the more specific \"10.3\"", got.Cycle)
	}
}

func TestDefaultCycleMatcherNoMatchAmongMultiple(t *testing.T) {
	cycles := []resolver.Cycle{{Cycle: "10.3"}, {Cycle: "9.12"}}
	_, ok := defaultCycleMatcher("7.0.0", cycles)
	if ok {
		t.Fatal("expected no match for a version outside every listed cycle")
	}
}

func TestDefaultCycleMatcherSingleCycleAlwaysMatches(t *testing.T) {
	// The GitHub Releases fallback always returns exactly one cycle (the
	// latest tag). An installed version that isn't that exact tag must
	// still resolve against it rather than being reported as unmatched.
	cycles := []resolver.Cycle{{Cycle: "v2.9.0", Latest: "v2.9.0"}}
	got, ok := defaultCycleMatcher("2.8.5", cycles)
	if !ok {
		t.Fatal("expected the single cycle to match regardless of name")
	}
	if got.Cycle != "v2.9.0" {
		t.Fatalf("got %q", got.Cycle)
	}
}

func TestDefaultCycleMatcherEmptyCyclesNoMatch(t *testing.T) {
	_, ok := defaultCycleMatcher("1.0.0", nil)
	if ok {
		t.Fatal("expected no match against an empty cycle list")
	}
}

func TestRegisterCycleMatcherIsUsedForItsProduct(t *testing.T) {
	const product = "test-fixture-product-registered-matcher"
	called := false
	RegisterCycleMatcher(product, func(_ string, _ []resolver.Cycle) (resolver.Cycle, bool) {
		called = true
		return resolver.Cycle{Cycle: "custom"}, true
	})

	got, ok := matchCycle(product, "whatever", nil)
	if !called || !ok || got.Cycle != "custom" {
		t.Fatalf("registered matcher was not used: called=%v ok=%v got=%+v", called, ok, got)
	}

	// Products without an override still get the default behaviour.
	_, ok = matchCycle("some-other-product-with-no-override", "1.0.0", []resolver.Cycle{{Cycle: "1.0"}})
	if !ok {
		t.Fatal("expected the default matcher for an unregistered product")
	}
}

func TestRegisterCycleMatcherPanicsOnDuplicate(t *testing.T) {
	const product = "test-fixture-product-duplicate-matcher"
	noop := func(string, []resolver.Cycle) (resolver.Cycle, bool) { return resolver.Cycle{}, false }
	RegisterCycleMatcher(product, noop)

	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic on duplicate registration")
		}
	}()
	RegisterCycleMatcher(product, noop)
}
