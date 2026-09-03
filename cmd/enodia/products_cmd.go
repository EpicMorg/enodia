// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/EpicMorg/enodia/internal/probe"
)

var productsCmd = &cobra.Command{
	Use:   "products",
	Short: "List supported products",
	Args:  cobra.NoArgs,
	RunE:  runProductsCmd,
}

func runProductsCmd(cmd *cobra.Command, _ []string) error {
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PRODUCT\tSUMMARY\tRESOLVER")
	for _, p := range probe.All() {
		m := p.Meta()
		res := "-"
		if m.DefaultResolver.Type != "" {
			res = m.DefaultResolver.Type + ":" + m.DefaultResolver.ID
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", m.Product, m.Summary, res)
	}
	return w.Flush()
}
