// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/EpicMorg/enodia/internal/evaluate"
	"github.com/EpicMorg/enodia/internal/render"
	"github.com/EpicMorg/enodia/internal/serve"
)

var (
	serveListenFlag   string
	serveIntervalFlag time.Duration
	serveWarnDaysFlag int
	serveFailOnFlag   []string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve the latest snapshot over HTTP, refreshed on a schedule",
	Long: `serve collects and evaluates on a timer (--interval) and serves whatever
the last successful cycle produced — a request never triggers a new
collection (D14: "a refresh button that polls your entire fleet on every
click is a self-inflicted denial of service"). There is no built-in
authentication or TLS: put this behind a reverse proxy.

Endpoints: / (HTML, all four views), /report.json, /metrics (Prometheus),
/healthz (liveness only — never touches the snapshot).`,
	Args: cobra.NoArgs,
	RunE: runServeCmd,
}

func init() {
	serveCmd.Flags().StringVar(&serveListenFlag, "listen", ":8080", "address to listen on")
	serveCmd.Flags().DurationVar(&serveIntervalFlag, "interval", time.Hour, "how often to refresh the snapshot")
	serveCmd.Flags().IntVar(&serveWarnDaysFlag, "warn-days", 0, "warn this many days before a lifecycle boundary is reached")
	serveCmd.Flags().StringSliceVar(&serveFailOnFlag, "fail-on", nil,
		"escalate an axis value to a hard failure (repeatable) — reflected in the served report, not a process exit code")
}

func runServeCmd(cmd *cobra.Command, _ []string) error {
	policy := evaluate.Policy{WarnDays: serveWarnDaysFlag, FailOn: serveFailOnFlag}
	res := buildResolver(cmd) // built once: its on-disk cache is meant to be reused across cycles, not rebuilt per tick

	collector := func(ctx context.Context) (render.Report, error) {
		// The config is reloaded fresh every cycle, so editing enodia.yaml
		// takes effect without restarting the server.
		inv, err := loadInventory(ctx, cmd, "")
		if err != nil {
			return render.Report{}, err
		}
		assessments := assess(ctx, inv, policy, res)
		return buildReport(inv, assessments), nil
	}

	if err := serve.Run(cmd.Context(), collector, serve.Options{
		Addr:     serveListenFlag,
		Interval: serveIntervalFlag,
		Warn:     warnPrinter(cmd),
	}); err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	return nil
}
