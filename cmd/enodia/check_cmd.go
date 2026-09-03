// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/EpicMorg/enodia/internal/evaluate"
)

var (
	checkFromFlag     string
	checkWarnDaysFlag int
	checkFailOnFlag   []string
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Assess targets against their lifecycle calendars",
	Long: `check evaluates the patch, lifecycle and newer-branch axes (D6) for every
target as of the moment its data was collected. Without --from it collects
first, in this same process — not a second code path (D4). With --from it
reads an existing inventory and only ever reaches the network for the
lifecycle resolver.`,
	Args: cobra.NoArgs,
	RunE: runCheckCmd,
}

func init() {
	checkCmd.Flags().StringVar(&checkFromFlag, "from", "", "read an existing inventory instead of collecting")
	checkCmd.Flags().IntVar(&checkWarnDaysFlag, "warn-days", 0, "warn this many days before a lifecycle boundary is reached")
	checkCmd.Flags().StringSliceVar(&checkFailOnFlag, "fail-on", nil,
		`escalate an axis value to a hard failure, e.g. --fail-on=patch:behind (repeatable)`)
}

func runCheckCmd(cmd *cobra.Command, _ []string) error {
	inv, err := loadInventory(cmd, checkFromFlag)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}

	policy := evaluate.Policy{WarnDays: checkWarnDaysFlag, FailOn: checkFailOnFlag}
	assessments := assess(cmd, inv, policy, buildResolver(cmd))

	if err := printAssessments(cmd.OutOrStdout(), assessments); err != nil {
		return &ExitError{Code: 1, Err: err}
	}

	if code := severityExitCode(worstSeverity(assessments)); code != 0 {
		return &ExitError{Code: code}
	}
	return nil
}

// printAssessments is a minimal, compact report — internal/render (see
// docs/ROADMAP.md, "Then — render") is the real table/JSON/HTML renderer;
// this exists so check is useful before that lands.
func printAssessments(w io.Writer, assessments []evaluate.Assessment) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPRODUCT\tPATCH\tLIFECYCLE\tBRANCH\tSEVERITY\tREASON")
	for _, a := range assessments {
		reason := string(a.Reason)
		if reason == "" {
			reason = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			a.ID, a.Product, a.Patch, a.Lifecycle, a.Branch, a.OverallSeverity(), reason)
	}
	return tw.Flush()
}
