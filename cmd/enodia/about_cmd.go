// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	_ "embed"
	"fmt"
	"runtime"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/EpicMorg/enodia/internal/probe"
)

//go:embed ascii.txt
var asciiLogo string

var aboutCmd = &cobra.Command{
	Use:   "about",
	Short: "Show the enodia logo and build information",
	Args:  cobra.NoArgs,
	RunE:  runAboutCmd,
}

func runAboutCmd(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	fmt.Fprintln(out, asciiLogo)
	fmt.Fprintln(out)

	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "Version\t%s\n", buildVersion)
	fmt.Fprintf(w, "Commit\t%s\n", buildCommit)
	fmt.Fprintf(w, "Built\t%s\n", buildDate)
	fmt.Fprintf(w, "Go\t%s\n", runtime.Version())
	fmt.Fprintf(w, "Platform\t%s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(w, "Products\t%d\n", len(probe.All()))
	fmt.Fprintf(w, "License\tAGPL-3.0-or-later\n")
	fmt.Fprintf(w, "Repository\thttps://github.com/EpicMorg/enodia\n")
	return w.Flush()
}
