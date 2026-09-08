// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/EpicMorg/enodia/internal/evaluate"
	"github.com/EpicMorg/enodia/internal/history"
	"github.com/EpicMorg/enodia/internal/render"
)

var (
	historyDirFlag      string
	historyFormatFlag   string
	historyOutputFlag   string
	historyWarnDaysFlag int
	historyFailOnFlag   []string
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "Show each target's assessment history across a directory of dated inventories",
	Long: `history reads every "*.jsonl" file in --dir and evaluates each one against
its own collection time (D8) — not today — building one timeline per target
ID. docs/ROADMAP.md's own words: "a directory of dated inventories is
already most of it"; producing that directory needs no code at all, just
"enodia collect -o \"$(date +%F).jsonl\"" on a schedule. This command is
the other half: reading many of them back as one history.`,
	Args: cobra.NoArgs,
	RunE: runHistoryCmd,
}

func init() {
	historyCmd.Flags().StringVar(&historyDirFlag, "dir", "", "directory of dated *.jsonl inventories (required)")
	historyCmd.Flags().StringVar(&historyFormatFlag, "format", "table", "output format: table or json")
	historyCmd.Flags().StringVarP(&historyOutputFlag, "output", "o", "-", "output file, or - for stdout")
	historyCmd.Flags().IntVar(&historyWarnDaysFlag, "warn-days", 0, "warn this many days before a lifecycle boundary is reached")
	historyCmd.Flags().StringSliceVar(&historyFailOnFlag, "fail-on", nil, "escalate an axis value to a hard failure (repeatable)")
}

func runHistoryCmd(cmd *cobra.Command, _ []string) error {
	if historyDirFlag == "" {
		return &ExitError{Code: 2, Err: fmt.Errorf("--dir is required")}
	}
	writeFormat, ok := historyFormats[historyFormatFlag]
	if !ok {
		return &ExitError{Code: 2, Err: fmt.Errorf(`format %q is not supported; use "table" or "json"`, historyFormatFlag)}
	}

	files, err := history.LoadDir(historyDirFlag)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}

	policy := evaluate.Policy{WarnDays: historyWarnDaysFlag, FailOn: historyFailOnFlag}
	timelines := history.Build(cmd.Context(), files, buildResolver(cmd), policy)
	report := render.HistoryReport{
		GeneratedAt: time.Now().UTC(),
		Tool:        "enodia/" + buildVersion,
		Timelines:   timelines,
	}

	out := cmd.OutOrStdout()
	if historyOutputFlag != "" && historyOutputFlag != "-" {
		f, err := os.Create(historyOutputFlag)
		if err != nil {
			return &ExitError{Code: 1, Err: err}
		}
		defer f.Close()
		out = f
	}

	if err := writeFormat(out, report); err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	return nil
}

var historyFormats = map[string]func(io.Writer, render.HistoryReport) error{
	"table": render.HistoryTable,
	"json":  render.HistoryJSON,
}
