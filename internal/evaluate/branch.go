// SPDX-License-Identifier: AGPL-3.0-or-later

package evaluate

import (
	"github.com/EpicMorg/enodia/internal/resolver"
	"github.com/EpicMorg/enodia/internal/version"
)

// evaluateBranch reports whether a release line newer than matchedCycle
// exists among cycles. Cycle names are themselves version-shaped
// ("10.3", "26.04", ...), so version.Compare orders them directly — no
// separate comparison scheme is needed.
func evaluateBranch(matchedCycle string, cycles []resolver.Cycle) Branch {
	newerExists := false
	newerLTS := false

	for _, c := range cycles {
		if c.Cycle == matchedCycle {
			continue
		}
		cmp, ok := version.Compare(c.Cycle, matchedCycle)
		if !ok || cmp <= 0 {
			continue
		}
		newerExists = true
		if c.LTS != nil && c.LTS.Bool {
			newerLTS = true
		}
	}

	switch {
	case newerLTS:
		return BranchNewerLTS
	case newerExists:
		return BranchNewer
	default:
		return BranchLatest
	}
}
