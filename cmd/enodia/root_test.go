// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"github.com/spf13/cobra"
)

func hasSubcommand(parent *cobra.Command, name string) bool {
	for _, c := range parent.Commands() {
		if c.Name() == name {
			return true
		}
	}
	return false
}

func TestRootCmdHasEveryRoadmapSubcommand(t *testing.T) {
	want := []string{"collect", "check", "export", "config", "products", "version"}
	for _, name := range want {
		if !hasSubcommand(rootCmd, name) {
			t.Errorf("rootCmd is missing the %q subcommand", name)
		}
	}
}

func TestConfigCmdHasEverySubcommand(t *testing.T) {
	want := []string{"path", "validate", "resolve"}
	for _, name := range want {
		if !hasSubcommand(configCmd, name) {
			t.Errorf("config is missing the %q subcommand", name)
		}
	}
}
