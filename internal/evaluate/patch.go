// SPDX-License-Identifier: AGPL-3.0-or-later

package evaluate

import "github.com/EpicMorg/enodia/internal/version"

// evaluatePatch compares the observed version against the latest release
// published in its matched cycle.
func evaluatePatch(observedNormalized, latestInCycle string) Patch {
	latest := version.Clean(latestInCycle)
	cmp, ok := version.Compare(observedNormalized, latest)
	if !ok {
		return PatchUnknown
	}
	switch {
	case cmp == 0:
		return PatchCurrent
	case cmp < 0:
		return PatchBehind
	default:
		return PatchAhead
	}
}
