// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"github.com/spf13/cobra"

	"github.com/EpicMorg/enodia/internal/evaluate"
	"github.com/EpicMorg/enodia/internal/render"
	"github.com/EpicMorg/enodia/internal/settings"
)

var (
	checkFromFlag     string
	checkViewFlag     string
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
lifecycle resolver.

--view selects the table focus: compact (default), lifecycle, drift, or
fleet — the offline-only view of version spread across a product's
instances. When --view is not passed, settings.yaml's render.default_view
applies instead of the compact default, if set.`,
	Args: cobra.NoArgs,
	RunE: runCheckCmd,
}

func init() {
	checkCmd.Flags().StringVar(&checkFromFlag, "from", "", "read an existing inventory instead of collecting")
	checkCmd.Flags().StringVar(&checkViewFlag, "view", string(render.ViewCompact),
		"table view: compact, lifecycle, drift, or fleet")
	checkCmd.Flags().IntVar(&checkWarnDaysFlag, "warn-days", 0, "warn this many days before a lifecycle boundary is reached")
	checkCmd.Flags().StringSliceVar(&checkFailOnFlag, "fail-on", nil,
		`escalate an axis value to a hard failure, e.g. --fail-on=patch:behind (repeatable)`)
}

func runCheckCmd(cmd *cobra.Command, _ []string) error {
	inv, err := loadInventory(cmd.Context(), cmd, checkFromFlag)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}

	view := checkViewFlag
	if !cmd.Flags().Changed("view") {
		st, err := settings.Resolve(settingsFlag)
		if err != nil {
			return &ExitError{Code: 1, Err: err}
		}
		if st.Render.DefaultView != "" {
			view = st.Render.DefaultView
		}
	}

	policy := evaluate.Policy{WarnDays: checkWarnDaysFlag, FailOn: checkFailOnFlag}
	assessments := assess(cmd.Context(), inv, policy, buildResolver(cmd))

	if err := render.Table(cmd.OutOrStdout(), render.View(view), buildReport(inv, assessments)); err != nil {
		return &ExitError{Code: 2, Err: err}
	}

	if code := severityExitCode(worstSeverity(assessments)); code != 0 {
		return &ExitError{Code: code}
	}
	return nil
}
