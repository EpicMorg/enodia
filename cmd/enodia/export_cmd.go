// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/EpicMorg/enodia/internal/evaluate"
	"github.com/EpicMorg/enodia/internal/render"
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
	Short: "Export a report as JSON, a Prometheus textfile, or single-file HTML",
	Long: `export writes one self-contained file (D14: nothing here serves it —
nginx, a cron job, or a systemd timer regenerating it is what does).

--format selects json, prometheus, or html.`,
	Args: cobra.NoArgs,
	RunE: runExportCmd,
}

func init() {
	exportCmd.Flags().StringVar(&exportFromFlag, "from", "", "read an existing inventory instead of collecting")
	exportCmd.Flags().StringVar(&exportFormatFlag, "format", "json", "output format: json, prometheus, or html")
	exportCmd.Flags().StringVarP(&exportOutputFlag, "output", "o", "-", "output file, or - for stdout")
	exportCmd.Flags().IntVar(&exportWarnDaysFlag, "warn-days", 0, "warn this many days before a lifecycle boundary is reached")
	exportCmd.Flags().StringSliceVar(&exportFailOnFlag, "fail-on", nil, "escalate an axis value to a hard failure (repeatable)")
}

func runExportCmd(cmd *cobra.Command, _ []string) error {
	writeFormat, ok := exportFormats[exportFormatFlag]
	if !ok {
		return &ExitError{Code: 2, Err: fmt.Errorf(
			`format %q is not supported; use "json", "prometheus", or "html"`, exportFormatFlag)}
	}

	inv, err := loadInventory(cmd.Context(), cmd, exportFromFlag)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	policy := evaluate.Policy{WarnDays: exportWarnDaysFlag, FailOn: exportFailOnFlag}
	assessments := assess(cmd.Context(), inv, policy, buildResolver(cmd))

	out := cmd.OutOrStdout()
	if exportOutputFlag != "" && exportOutputFlag != "-" {
		f, err := os.Create(exportOutputFlag)
		if err != nil {
			return &ExitError{Code: 1, Err: err}
		}
		defer f.Close()
		out = f
	}

	if err := writeFormat(out, buildReport(inv, assessments)); err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	return nil
}

// exportFormats maps --format to the render function that produces it.
var exportFormats = map[string]func(io.Writer, render.Report) error{
	"json":       render.JSON,
	"prometheus": render.Prometheus,
	"html":       render.HTML,
}
