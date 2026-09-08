// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

// genManCmd is a build-time tool, not a user-facing feature: it renders
// rootCmd's own tree into troff man pages via cobra/doc (a subpackage of the
// cobra dependency already approved for CLI parsing, not a new dependency).
// Hidden from --help because a released binary shipping this command would
// otherwise imply "enodia gen-man" is something an end user might run — the
// Makefile's "man" target is the only intended caller (see .goreleaser.yaml's
// before.hooks, which runs that target before nfpm packages build/man/ into
// /usr/share/man/man1).
var genManCmd = &cobra.Command{
	Use:    "gen-man <output-dir>",
	Short:  "Generate man pages for the enodia command tree (build tooling, not for end users)",
	Hidden: true,
	Args:   cobra.ExactArgs(1),
	RunE:   runGenManCmd,
}

func init() {
	rootCmd.AddCommand(genManCmd)
}

func runGenManCmd(cmd *cobra.Command, args []string) error {
	dir := args[0]
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("gen-man: create output dir: %w", err)
	}

	header := &doc.GenManHeader{
		Title:   "ENODIA",
		Section: "1",
		Source:  "enodia " + buildVersion,
		Manual:  "Enodia Manual",
	}

	// rootCmd itself carries gen-man as a hidden subcommand; GenManTree
	// walks every command including hidden ones, so it would otherwise get
	// a man page of its own. Strip it for the duration of generation
	// rather than teaching GenManTree about an exclusion list. Going
	// through cmd.Parent()/cmd (the *this* command, handed in by cobra)
	// rather than the package-level rootCmd/genManCmd vars sidesteps a
	// genManCmd->runGenManCmd->genManCmd initialization cycle the compiler
	// otherwise flags — cmd is the exact same object at runtime.
	root := cmd.Parent()
	root.RemoveCommand(cmd)
	defer root.AddCommand(cmd)

	if err := doc.GenManTree(root, header, dir); err != nil {
		return fmt.Errorf("gen-man: %w", err)
	}
	return nil
}
