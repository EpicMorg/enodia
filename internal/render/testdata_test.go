// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"time"

	"github.com/EpicMorg/enodia/internal/evaluate"
	"github.com/EpicMorg/enodia/internal/probe"
)

// sampleReport gives every renderer a small but representative mix: a
// current target, a behind-and-nearing-EOL target, a failed probe, and two
// instances of one product on different versions (for the fleet view).
func sampleReport() Report {
	asOf := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	eol := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	support := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	return Report{
		GeneratedAt: asOf,
		AsOf:        asOf,
		Tool:        "enodia/test",
		Observations: []probe.Observation{
			{ID: "jira-a", Product: "jira", Version: "10.3.1", Normalized: "10.3.1"},
			{ID: "jira-b", Product: "jira", Version: "10.3.2", Normalized: "10.3.2"},
			{ID: "confluence-a", Product: "confluence", Version: "9.2.1", Normalized: "9.2.1"},
			{ID: "down", Product: "jira", Error: "connection refused", ErrorKind: "unreachable"},
		},
		Assessments: []evaluate.Assessment{
			{
				ID: "jira-a", Product: "jira",
				Patch: evaluate.PatchBehind, Lifecycle: evaluate.LifecycleSecurity, Branch: evaluate.BranchLatest,
				MatchedCycle: "10.3", LatestInCycle: "10.3.2", EOLDate: &eol, SupportEnds: &support,
				PatchSeverity: evaluate.SeverityWarn, LifecycleSeverity: evaluate.SeverityWarn,
			},
			{
				ID: "jira-b", Product: "jira",
				Patch: evaluate.PatchCurrent, Lifecycle: evaluate.LifecycleSecurity, Branch: evaluate.BranchLatest,
				MatchedCycle: "10.3", LatestInCycle: "10.3.2", EOLDate: &eol, SupportEnds: &support,
				LifecycleSeverity: evaluate.SeverityWarn,
			},
			{
				ID: "confluence-a", Product: "confluence",
				Patch: evaluate.PatchCurrent, Lifecycle: evaluate.LifecycleActive, Branch: evaluate.BranchNewerLTS,
				MatchedCycle: "9.2", LatestInCycle: "9.2.1",
				BranchSeverity: evaluate.SeverityWarn,
			},
			{
				ID: "down", Product: "jira",
				Patch: evaluate.PatchUnknown, Lifecycle: evaluate.LifecycleUnknown, Branch: evaluate.BranchUnknown,
				Reason: evaluate.ReasonProbeFailed, ReasonSeverity: evaluate.SeverityWarn,
			},
		},
	}
}
