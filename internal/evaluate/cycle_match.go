// SPDX-License-Identifier: AGPL-3.0-or-later

package evaluate

import (
	"github.com/EpicMorg/enodia/internal/resolver"
	"github.com/EpicMorg/enodia/internal/version"
)

// CycleMatcher decides which of a product's published cycles a raw,
// normalized version belongs to. The default (version.MatchCycle's
// numeric-prefix matching) fits every product implemented so far; this hook
// exists for the vendor that eventually doesn't — see D2's registry.go for
// the same explicit-over-implicit rationale.
type CycleMatcher func(normalizedVersion string, cycles []resolver.Cycle) (resolver.Cycle, bool)

// cycleMatchers holds per-product overrides. Empty today: no shipped probe
// needs one yet.
var cycleMatchers = map[string]CycleMatcher{}

// RegisterCycleMatcher installs a per-product override, called explicitly
// (not via init()) so a pull request adding one is visible in the diff.
func RegisterCycleMatcher(product string, m CycleMatcher) {
	if _, dup := cycleMatchers[product]; dup {
		panic("enodia: duplicate cycle matcher for product " + product)
	}
	cycleMatchers[product] = m
}

func matchCycle(product, normalizedVersion string, cycles []resolver.Cycle) (resolver.Cycle, bool) {
	if m, ok := cycleMatchers[product]; ok {
		return m(normalizedVersion, cycles)
	}
	return defaultCycleMatcher(normalizedVersion, cycles)
}

func defaultCycleMatcher(normalizedVersion string, cycles []resolver.Cycle) (resolver.Cycle, bool) {
	if len(cycles) == 1 {
		// A single-cycle source — the GitHub Releases fallback always
		// reports exactly one, the latest tag — has no other branch to
		// compare against, so that cycle is the comparison point
		// regardless of whether its name looks like the observed
		// version's branch.
		return cycles[0], true
	}

	names := make([]string, len(cycles))
	for i, c := range cycles {
		names[i] = c.Cycle
	}
	name, ok := version.MatchCycle(normalizedVersion, names)
	if !ok {
		return resolver.Cycle{}, false
	}
	for _, c := range cycles {
		if c.Cycle == name {
			return c, true
		}
	}
	return resolver.Cycle{}, false
}
