// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the enodia version",
	Args:  cobra.NoArgs,
	RunE:  runVersionCmd,
}

func runVersionCmd(cmd *cobra.Command, _ []string) error {
	fmt.Fprintln(cmd.OutOrStdout(), buildVersion)
	return nil
}
