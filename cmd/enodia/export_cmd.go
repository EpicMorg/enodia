// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/EpicMorg/enodia/internal/evaluate"
	"github.com/EpicMorg/enodia/internal/render"
	"github.com/EpicMorg/enodia/internal/settings"
)

var (
	exportFromFlag     string
	exportFormatFlag   string
	exportOutputFlag   string
	exportViewFlag     string
	exportWarnDaysFlag int
	exportFailOnFlag   []string
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export a report as JSON, a Prometheus textfile, or single-file HTML",
	Long: `export writes one self-contained file (D14: nothing here serves it —
nginx, a cron job, or a systemd timer regenerating it is what does).

--format selects json, prometheus, or html. When --format is not passed,
settings.yaml's export.default_format applies instead, if set; the
built-in default stays json either way.

--view restricts an html export to one view (compact, lifecycle, drift, or
fleet) instead of all four stacked sections; ignored by json/prometheus,
which always carry every observation and assessment. When --view is not
passed, settings.yaml's html.view applies instead, if set. settings.yaml
also controls whether an html export is the default fully offline single
file (html.assets: inline) or pulls Bootstrap and a Bootswatch theme from
a CDN (html.assets: cdn, html.theme) — see docs/DECISIONS.md D19.`,
	Args: cobra.NoArgs,
	RunE: runExportCmd,
}

func init() {
	exportCmd.Flags().StringVar(&exportFromFlag, "from", "", "read an existing inventory instead of collecting")
	exportCmd.Flags().StringVar(&exportFormatFlag, "format", "json", "output format: json, prometheus, or html")
	exportCmd.Flags().StringVarP(&exportOutputFlag, "output", "o", "-", "output file, or - for stdout")
	exportCmd.Flags().StringVar(&exportViewFlag, "view", "",
		"html only: restrict the report to one view (compact, lifecycle, drift, fleet); default is all four")
	exportCmd.Flags().IntVar(&exportWarnDaysFlag, "warn-days", 0, "warn this many days before a lifecycle boundary is reached")
	exportCmd.Flags().StringSliceVar(&exportFailOnFlag, "fail-on", nil, "escalate an axis value to a hard failure (repeatable)")
}

func runExportCmd(cmd *cobra.Command, _ []string) error {
	// format falls back to settings.yaml's export.default_format only when
	// --format itself was never passed — an explicit --format always wins,
	// exactly like --view already does against html.view. This is also why
	// settings is resolved here at all rather than only inside the html
	// branch below: "which format" is settings' business the moment
	// --format is left unset, not only once html is already decided.
	format := exportFormatFlag
	var st *settings.Settings
	if !cmd.Flags().Changed("format") {
		resolved, err := settings.Resolve(settingsFlag)
		if err != nil {
			return &ExitError{Code: 1, Err: err}
		}
		st = resolved
		if st.Export.DefaultFormat != "" {
			format = st.Export.DefaultFormat
		}
	}

	if format != "html" && exportFormats[format] == nil {
		return &ExitError{Code: 2, Err: fmt.Errorf(
			`format %q is not supported; use "json", "prometheus", or "html"`, format)}
	}

	inv, err := loadInventory(cmd.Context(), cmd, exportFromFlag)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	policy := evaluate.Policy{WarnDays: exportWarnDaysFlag, FailOn: exportFailOnFlag}
	assessments := assess(cmd.Context(), inv, policy, buildResolver(cmd))
	report := buildReport(inv, assessments)

	out := cmd.OutOrStdout()
	if exportOutputFlag != "" && exportOutputFlag != "-" {
		f, err := os.Create(exportOutputFlag)
		if err != nil {
			return &ExitError{Code: 1, Err: err}
		}
		defer f.Close()
		out = f
	}

	if format == "html" {
		if st == nil { // --format html was passed explicitly; not resolved above
			resolved, err := settings.Resolve(settingsFlag)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			st = resolved
		}
		if err := render.HTML(out, report, htmlExportOptions(cmd, st)); err != nil {
			return &ExitError{Code: 1, Err: err}
		}
		return nil
	}

	if err := exportFormats[format](out, report); err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	return nil
}

// exportFormats maps json/prometheus's --format to the render function
// that produces it. html is handled separately in runExportCmd: it alone
// needs HTMLOptions built from settings.yaml and --view, so its signature
// no longer fits this map.
var exportFormats = map[string]func(io.Writer, render.Report) error{
	"json":       render.JSON,
	"prometheus": render.Prometheus,
}

// htmlExportOptions resolves export --format html's asset mode, view,
// theme and CDN from st (already resolved by the caller): --view (if
// passed) beats settings.yaml's html.view, which beats "" (all four
// sections, the original behaviour). Assets/theme/CDN come from
// settings.yaml only, no flag — D19 treats them as a per-operator default
// to set once, not a per-export choice.
func htmlExportOptions(cmd *cobra.Command, st *settings.Settings) render.HTMLOptions {
	view := st.HTML.View
	if cmd.Flags().Changed("view") {
		view = exportViewFlag
	}

	return render.HTMLOptions{
		Assets: st.HTML.Assets,
		View:   render.View(view),
		Theme:  st.EffectiveTheme(),
		CDN:    st.HTML.CDN,
	}
}
