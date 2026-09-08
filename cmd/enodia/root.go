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

// settingsFlag is the --settings persistent flag: same rule as configFlag
// when set explicitly (see internal/settings.Locate), but unlike config an
// entirely missing settings.yaml is normal, not an error (D19) — it just
// means every display default stays built-in.
var settingsFlag string

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
	rootCmd.PersistentFlags().StringVar(&settingsFlag, "settings", "",
		"path to settings.yaml (default: search standard locations; missing is not an error)")

	rootCmd.AddCommand(collectCmd, checkCmd, exportCmd, serveCmd, historyCmd, configCmd, productsCmd, versionCmd, aboutCmd)
}
