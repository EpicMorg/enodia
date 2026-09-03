// SPDX-License-Identifier: AGPL-3.0-or-later

package evaluate

import "time"

// Policy turns axis values into a Severity. The zero value is permissive:
// every axis gets its ordinary default severity, nothing is escalated, and
// no early warning fires.
type Policy struct {
	// WarnDays starts a Warn on the Lifecycle axis this many days before a
	// boundary (active support ending, or EOL) is reached, so operators see
	// it coming rather than being surprised on the day it lands. Zero
	// disables early warning; only a boundary already crossed is flagged.
	WarnDays int

	// FailOn lists "axis:value" pairs that must be treated as SeverityFail
	// regardless of that axis's ordinary default — e.g. "patch:behind" to
	// make an org that requires staying current treat any lag as a hard
	// failure, or "branch:newer" to fail on any available upgrade at all.
	// "reason:cycle_unmatched" and friends work the same way against
	// Reason. An axis value not listed here keeps its default severity.
	FailOn []string
}

// escalate returns SeverityFail if "axis:value" is listed in FailOn,
// otherwise base.
func (p Policy) escalate(axis, value string, base Severity) Severity {
	key := axis + ":" + value
	for _, f := range p.FailOn {
		if f == key {
			return SeverityFail
		}
	}
	return base
}

func defaultPatchSeverity(p Patch) Severity {
	if p == PatchBehind {
		return SeverityWarn
	}
	return SeverityNone
}

func defaultLifecycleSeverity(l Lifecycle) Severity {
	switch l {
	case LifecycleSecurity:
		return SeverityWarn
	case LifecycleEOL:
		return SeverityFail
	default:
		return SeverityNone
	}
}

func defaultBranchSeverity(b Branch) Severity {
	switch b {
	case BranchNewer:
		return SeverityInfo
	case BranchNewerLTS:
		return SeverityWarn
	default:
		return SeverityNone
	}
}

// defaultReasonSeverity gives probe failures and mismatched cycles a floor
// above SeverityNone even though their axes all read Unknown — an unknown
// caused by "nothing to compare against" (ReasonNoResolver) is a normal,
// quiet state, but one caused by an unreachable probe or a resolver's data
// simply not matching is not, and must not vanish into a silent Unknown.
func defaultReasonSeverity(r Reason) Severity {
	switch r {
	case ReasonProbeFailed, ReasonCycleUnmatched:
		return SeverityWarn
	case ReasonResolverError:
		return SeverityInfo
	default: // ReasonNone, ReasonSkipped, ReasonNoResolver
		return SeverityNone
	}
}

// applySeverities computes every per-axis severity: the default for the
// axis's value, escalated to Fail by policy.FailOn, then (Lifecycle only)
// raised early by WarnDays.
func (a *Assessment) applySeverities(policy Policy, asOf time.Time) {
	a.PatchSeverity = policy.escalate("patch", string(a.Patch), defaultPatchSeverity(a.Patch))
	a.LifecycleSeverity = policy.escalate("lifecycle", string(a.Lifecycle), defaultLifecycleSeverity(a.Lifecycle))
	a.BranchSeverity = policy.escalate("branch", string(a.Branch), defaultBranchSeverity(a.Branch))
	a.ReasonSeverity = policy.escalate("reason", string(a.Reason), defaultReasonSeverity(a.Reason))

	if policy.WarnDays <= 0 {
		return
	}
	threshold := time.Duration(policy.WarnDays) * 24 * time.Hour

	if a.EOLDate != nil && a.Lifecycle != LifecycleEOL && !a.EOLDate.Before(asOf) && a.EOLDate.Sub(asOf) <= threshold {
		a.LifecycleSeverity = maxSeverity(a.LifecycleSeverity, SeverityWarn)
	}
	if a.SupportEnds != nil && a.Lifecycle == LifecycleActive && !a.SupportEnds.Before(asOf) && a.SupportEnds.Sub(asOf) <= threshold {
		a.LifecycleSeverity = maxSeverity(a.LifecycleSeverity, SeverityWarn)
	}
}
