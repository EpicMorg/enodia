// SPDX-License-Identifier: AGPL-3.0-or-later

package evaluate

import (
	"time"

	"github.com/EpicMorg/enodia/internal/resolver"
)

// evaluateLifecycle computes the Lifecycle axis for the matched cycle as of
// asOf, plus the concrete dates (if any) behind it, for callers that want to
// show or warn ahead of them.
func evaluateLifecycle(c resolver.Cycle, asOf time.Time) (Lifecycle, *time.Time, *time.Time) {
	eolDate := flagDate(c.EOL)
	supportDate := flagDate(c.Support)

	if c.EOL == nil {
		// The source never reported eol at all — the GitHub Releases
		// fallback, e.g. Patch and Branch can still be meaningful; only
		// Lifecycle specifically is unknown here.
		return LifecycleUnknown, eolDate, supportDate
	}
	if isPast(c.EOL, asOf) {
		return LifecycleEOL, eolDate, supportDate
	}
	if isPast(c.Support, asOf) {
		return LifecycleSecurity, eolDate, supportDate
	}
	return LifecycleActive, eolDate, supportDate
}

// flagDate extracts a concrete time from a Flag, if it carries a date.
func flagDate(f *resolver.Flag) *time.Time {
	if f == nil || !f.IsDate {
		return nil
	}
	d := f.Date
	return &d
}

// isPast reports whether f pins a concrete date at or before asOf.
//
// A bare boolean, either value, is deliberately NOT treated as "already
// happened": endoflife.date reports e.g. "support": true for cycles that are
// simply still fully supported with no transition date assigned yet, not
// for ones whose support has already ended (confirmed against the live API:
// Redis's newest, most-active cycle reports support:true). Only a date
// moves a cycle from one lifecycle phase to the next; a bare bool is data
// worth keeping on the Flag for a caller that wants it, but not a timeline
// event on its own.
func isPast(f *resolver.Flag, asOf time.Time) bool {
	return f != nil && f.IsDate && !asOf.Before(f.Date)
}
