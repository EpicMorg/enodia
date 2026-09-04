// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

// testCmd builds a bare cobra.Command wired to buffers and a background
// context, the way each command's real *cobra.Command would be when cobra
// invokes it — enough for calling a runXCmd function directly without going
// through flag parsing.
func testCmd(t *testing.T) (cmd *cobra.Command, stdout, stderr *bytes.Buffer) {
	t.Helper()
	stdout, stderr = &bytes.Buffer{}, &bytes.Buffer{}
	cmd = &cobra.Command{}
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.SetContext(context.Background())
	return cmd, stdout, stderr
}

// withConfigFlag points the --config global at path for the duration of the
// test, restoring the previous value afterwards — configFlag is a package
// var shared with the real CLI wiring.
func withConfigFlag(t *testing.T, path string) {
	t.Helper()
	prev := configFlag
	configFlag = path
	t.Cleanup(func() { configFlag = prev })
}

// withSettingsFlag points the --settings global at path for the duration of
// the test, restoring the previous value afterwards — settingsFlag is a
// package var shared with the real CLI wiring, same pattern as
// withConfigFlag.
func withSettingsFlag(t *testing.T, path string) {
	t.Helper()
	prev := settingsFlag
	settingsFlag = path
	t.Cleanup(func() { settingsFlag = prev })
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
