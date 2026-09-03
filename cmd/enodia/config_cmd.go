// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/EpicMorg/enodia/internal/config"
	"github.com/EpicMorg/enodia/internal/probe"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Inspect and validate the config file",
}

var configPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Print which config file would be used",
	Args:  cobra.NoArgs,
	RunE:  runConfigPathCmd,
}

var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate the config file and its credential references",
	Args:  cobra.NoArgs,
	RunE:  runConfigValidateCmd,
}

var configResolveCmd = &cobra.Command{
	Use:   "resolve",
	Short: "Discover the scheme (https/http) for targets with no explicit one",
	Long: `resolve tries https, then http (D12: never http first, since that would put
a credential on the wire in the clear), for every target whose address has
no explicit scheme. It sends no credentials and does not modify the config
file — it only reports what scheme each target would use.`,
	Args: cobra.NoArgs,
	RunE: runConfigResolveCmd,
}

func init() {
	configCmd.AddCommand(configPathCmd, configValidateCmd, configResolveCmd)
}

func runConfigPathCmd(cmd *cobra.Command, _ []string) error {
	path, err := config.Locate(configFlag)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	fmt.Fprintln(cmd.OutOrStdout(), path)
	return nil
}

func runConfigValidateCmd(cmd *cobra.Command, _ []string) error {
	path, err := config.Locate(configFlag)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	cfg, err := config.Load(path)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	if _, err := cfg.Build(warnPrinter(cmd)); err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s: OK (%d target(s))\n", path, len(cfg.Targets))
	return nil
}

func runConfigResolveCmd(cmd *cobra.Command, _ []string) error {
	path, err := config.Locate(configFlag)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	cfg, err := config.Load(path)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	targets, err := cfg.Build(warnPrinter(cmd))
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}

	ctx := cmd.Context()
	out := cmd.OutOrStdout()
	for _, t := range targets {
		if probe.HasScheme(t.Address) {
			continue
		}
		scheme, err := resolveScheme(ctx, t.Address, t.TLS, t.Timeout)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s: %v\n", t.ID, err)
			continue
		}
		fmt.Fprintf(out, "%s: %s (add scheme explicitly to silence this check)\n", t.ID, scheme)
	}
	return nil
}
