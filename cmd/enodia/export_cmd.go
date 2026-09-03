// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/EpicMorg/enodia/internal/evaluate"
)

var (
	exportFromFlag     string
	exportFormatFlag   string
	exportOutputFlag   string
	exportWarnDaysFlag int
	exportFailOnFlag   []string
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export assessments",
	Long: `export currently supports --format json. Prometheus textfile and
single-file HTML are internal/render's job (docs/ROADMAP.md, "Then —
render") and are not implemented yet.`,
	Args: cobra.NoArgs,
	RunE: runExportCmd,
}

func init() {
	exportCmd.Flags().StringVar(&exportFromFlag, "from", "", "read an existing inventory instead of collecting")
	exportCmd.Flags().StringVar(&exportFormatFlag, "format", "json", `output format ("json" for now)`)
	exportCmd.Flags().StringVarP(&exportOutputFlag, "output", "o", "-", "output file, or - for stdout")
	exportCmd.Flags().IntVar(&exportWarnDaysFlag, "warn-days", 0, "warn this many days before a lifecycle boundary is reached")
	exportCmd.Flags().StringSliceVar(&exportFailOnFlag, "fail-on", nil, "escalate an axis value to a hard failure (repeatable)")
}

func runExportCmd(cmd *cobra.Command, _ []string) error {
	if exportFormatFlag != "json" {
		return &ExitError{Code: 2, Err: fmt.Errorf(
			"format %q is not implemented yet; only \"json\" is available until internal/render lands", exportFormatFlag)}
	}

	inv, err := loadInventory(cmd, exportFromFlag)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	policy := evaluate.Policy{WarnDays: exportWarnDaysFlag, FailOn: exportFailOnFlag}
	assessments := assess(cmd, inv, policy, buildResolver(cmd))

	out := cmd.OutOrStdout()
	if exportOutputFlag != "" && exportOutputFlag != "-" {
		f, err := os.Create(exportOutputFlag)
		if err != nil {
			return &ExitError{Code: 1, Err: err}
		}
		defer f.Close()
		out = f
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(assessments); err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	return nil
}
