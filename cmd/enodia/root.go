// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "github.com/spf13/cobra"

// buildVersion, buildCommit and buildDate are overridden at release time via
// -ldflags "-X main.buildVersion=... -X main.buildCommit=... -X main.buildDate=...".
// goreleaser wires these (see .goreleaser.yaml) — docs/ROADMAP.md, "Then —
// packaging".
var (
	buildVersion = "dev"
	buildCommit  = "unknown"
	buildDate    = "unknown"
)

// configFlag is the --config persistent flag: an explicit path that must
// exist (never a fallback — see internal/config.Locate), or empty to search
// the standard locations.
var configFlag string

var rootCmd = &cobra.Command{
	Use:   "enodia",
	Short: "Service inventory and lifecycle (EOL) monitoring",

	// A runtime error must not dump the whole help text into CI logs.
	SilenceUsage: true,
	// We print errors ourselves (see exitCode/main.go) so *ExitError's
	// chosen exit code and message stay in sync with what's printed.
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&configFlag, "config", "",
		"path to enodia.yaml (default: search standard locations)")

	rootCmd.AddCommand(collectCmd, checkCmd, exportCmd, serveCmd, historyCmd, configCmd, productsCmd, versionCmd)
}
