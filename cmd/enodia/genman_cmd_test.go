// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

func TestRunGenManCmd(t *testing.T) {
	root := &cobra.Command{Use: "enodia", Short: "test root"}
	self := &cobra.Command{Use: "gen-man <output-dir>", Hidden: true}
	root.AddCommand(self)

	dir := t.TempDir()
	if err := runGenManCmd(self, []string{dir}); err != nil {
		t.Fatalf("runGenManCmd: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "enodia.1")); err != nil {
		t.Fatalf("expected enodia.1 to be generated: %v", err)
	}

	found := false
	for _, c := range root.Commands() {
		if c == self {
			found = true
		}
	}
	if !found {
		t.Fatal("gen-man command was not restored as a child of root after generation")
	}
}
