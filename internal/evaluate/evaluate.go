// SPDX-License-Identifier: AGPL-3.0-or-later

// Package evaluate turns a probe observation and a product's lifecycle
// cycles into a verdict as of a given time.
//
// Per D6, patch/lifecycle/newer-branch are three independent axes, never
// collapsed into one status. Per D7, this package computes judgement —
// probe.Observation and resolver.Cycle stay pure fact; nothing upstream of
// here carries an opinion. Per D8, time is a parameter: Evaluate never calls
// time.Now(), so a run is reproducible a year later against the same
// inventory.
package evaluate

import (
	"time"

	"github.com/EpicMorg/enodia/internal/probe"
	"github.com/EpicMorg/enodia/internal/resolver"
	"github.com/EpicMorg/enodia/internal/version"
)

// Patch is how the observed version compares to the latest release in its
// own matched cycle.
type Patch string

const (
	PatchCurrent Patch = "current"
	PatchBehind  Patch = "behind"
	PatchAhead   Patch = "ahead" // release candidates and calendar lag are routine, not exotic
	PatchUnknown Patch = "unknown"
)

// Lifecycle is where the matched cycle sits in its support timeline as of
// asOf.
type Lifecycle string

const (
	LifecycleActive   Lifecycle = "active"
	LifecycleSecurity Lifecycle = "security"
	LifecycleEOL      Lifecycle = "eol"
	LifecycleUnknown  Lifecycle = "unknown"
)

// Branch is whether a newer release line than the matched cycle exists.
type Branch string

const (
	BranchLatest   Branch = "latest"
	BranchNewer    Branch = "newer"
	BranchNewerLTS Branch = "newer_lts" // a newer LTS specifically — the more actionable case
	BranchUnknown  Branch = "unknown"
)

// Reason names why the axes above are Unknown, when they are, for the three
// situations the roadmap calls out as needing to stay distinguishable rather
// than collapsing into one undifferentiated "unknown":
//
//   - ReasonProbeFailed: no version was observed at all — none of the three
//     axes can be computed, and this is a probe/reachability problem, not a
//     lifecycle one.
//   - ReasonNoResolver: the product has no lifecycle calendar, or the
//     resolver ran and simply returned nothing. Inventory-only; normal.
//   - ReasonResolverError: a calendar was expected but fetching it failed —
//     unlike ReasonNoResolver, this is worth a human noticing.
//   - ReasonCycleUnmatched: cycles exist, but the observed version doesn't
//     belong to any of them. Usually means something genuinely odd (a
//     version scheme change, a stale resolver cache) and must not be buried
//     under a bare "unknown".
type Reason string

const (
	ReasonNone           Reason = ""
	ReasonSkipped        Reason = "skipped" // probe.ErrSkipped: no credentials supplied, expected in shared configs
	ReasonProbeFailed    Reason = "probe_failed"
	ReasonNoResolver     Reason = "no_resolver"
	ReasonResolverError  Reason = "resolver_error"
	ReasonCycleUnmatched Reason = "cycle_unmatched"
)

// Severity is a policy's judgement of an axis or Reason. Kept per axis
// rather than collapsed (see Assessment), for the same reason D6 keeps the
// axes themselves separate.
type Severity string

const (
	SeverityNone Severity = "none"
	SeverityInfo Severity = "info"
	SeverityWarn Severity = "warn"
	SeverityFail Severity = "fail"
)

var severityRank = map[Severity]int{
	SeverityNone: 0,
	SeverityInfo: 1,
	SeverityWarn: 2,
	SeverityFail: 3,
}

func maxSeverity(a, b Severity) Severity {
	if severityRank[b] > severityRank[a] {
		return b
	}
	return a
}

// Max returns whichever of a and b is more severe. Exported for callers
// (the CLI's exit code, a summary line) that need to fold many Assessments
// into one worst case.
func Max(a, b Severity) Severity { return maxSeverity(a, b) }

// Input bundles the facts Evaluate needs. Nothing here is a judgement.
type Input struct {
	Observation probe.Observation

	// Resolver is the ResolverRef that was (or would have been) used to
	// fetch Cycles — normally probe.Meta.DefaultResolver. Its zero value
	// means the product has no lifecycle calendar.
	Resolver probe.ResolverRef

	// Cycles is what resolver.Resolve(ctx, Resolver) returned. Nil when
	// there is no calendar, or when ResolveErr is set.
	Cycles []resolver.Cycle

	// ResolveErr is the error resolver.Resolve returned, if any. Its
	// presence (as opposed to Resolver.Type == "") is what distinguishes
	// "no calendar exists" from "fetching the calendar failed".
	ResolveErr error
}

// Assessment is the verdict for one target as of one point in time.
type Assessment struct {
	ID      string
	Name    string
	Product string

	Patch     Patch
	Lifecycle Lifecycle
	Branch    Branch
	Reason    Reason

	MatchedCycle  string // the release branch the observed version matched, if any
	LatestInCycle string // the latest release published in MatchedCycle
	EOLDate       *time.Time
	SupportEnds   *time.Time // when active support ends (security-only begins)

	PatchSeverity     Severity
	LifecycleSeverity Severity
	BranchSeverity    Severity
	ReasonSeverity    Severity
}

// OverallSeverity is the worst of the four per-axis severities, for callers
// (the CLI's exit code, a summary line) that need one number. Assessment
// itself keeps them separate; this is a convenience, not the source of
// truth.
func (a Assessment) OverallSeverity() Severity {
	sev := a.PatchSeverity
	sev = maxSeverity(sev, a.LifecycleSeverity)
	sev = maxSeverity(sev, a.BranchSeverity)
	sev = maxSeverity(sev, a.ReasonSeverity)
	return sev
}

// Evaluate computes the Assessment for one observation as of asOf.
func Evaluate(in Input, asOf time.Time, policy Policy) Assessment {
	a := Assessment{
		ID:      in.Observation.ID,
		Name:    in.Observation.Name,
		Product: in.Observation.Product,
	}

	switch {
	case in.Observation.ErrorKind == "skipped":
		a.Reason = ReasonSkipped
	case !in.Observation.OK():
		a.Reason = ReasonProbeFailed
	case in.ResolveErr != nil:
		a.Reason = ReasonResolverError
	case len(in.Cycles) == 0:
		// Either Resolver.Type == "" (no calendar for this product) or the
		// resolver ran and simply found nothing to report — both are the
		// same "nothing to compare against" state from here.
		a.Reason = ReasonNoResolver
	}

	if a.Reason != ReasonNone {
		a.Patch, a.Lifecycle, a.Branch = PatchUnknown, LifecycleUnknown, BranchUnknown
		a.applySeverities(policy, asOf)
		return a
	}

	normalized := in.Observation.Normalized
	if normalized == "" {
		normalized = version.Clean(in.Observation.Version)
	}

	matched, ok := matchCycle(in.Observation.Product, normalized, in.Cycles)
	if !ok {
		a.Reason = ReasonCycleUnmatched
		a.Patch, a.Lifecycle, a.Branch = PatchUnknown, LifecycleUnknown, BranchUnknown
		a.applySeverities(policy, asOf)
		return a
	}

	a.MatchedCycle = matched.Cycle
	a.LatestInCycle = matched.Latest
	a.Patch = evaluatePatch(normalized, matched.Latest)
	a.Lifecycle, a.EOLDate, a.SupportEnds = evaluateLifecycle(matched, asOf)
	a.Branch = evaluateBranch(matched.Cycle, in.Cycles)

	a.applySeverities(policy, asOf)
	return a
}
