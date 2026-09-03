// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/EpicMorg/enodia/internal/inventory"
)

var collectOutputFlag string

var collectCmd = &cobra.Command{
	Use:   "collect",
	Short: "Probe every target in the config and write an inventory",
	Long: `collect only gathers facts (D4/D7): an unreachable target is recorded as
an observation with an error, not treated as a command failure. The exit
code reflects whether collection itself ran, not what it found — that
judgement is check's job.`,
	Args: cobra.NoArgs,
	RunE: runCollectCmd,
}

func init() {
	collectCmd.Flags().StringVarP(&collectOutputFlag, "output", "o", "-", "output file, or - for stdout")
}

func runCollectCmd(cmd *cobra.Command, _ []string) error {
	_, observations, err := collectObservations(cmd)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}

	out := cmd.OutOrStdout()
	if collectOutputFlag != "" && collectOutputFlag != "-" {
		f, err := os.Create(collectOutputFlag)
		if err != nil {
			return &ExitError{Code: 1, Err: err}
		}
		defer f.Close()
		out = f
	}

	w, err := inventory.NewWriter(out, "enodia/"+buildVersion, false)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	for _, o := range observations {
		if err := w.Write(o); err != nil {
			return &ExitError{Code: 1, Err: err}
		}
	}
	return nil
}
