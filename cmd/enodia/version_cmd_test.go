// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"
)

func TestRunVersionCmd(t *testing.T) {
	cmd, stdout, _ := testCmd(t)
	if err := runVersionCmd(cmd, nil); err != nil {
		t.Fatalf("runVersionCmd: %v", err)
	}
	if got := strings.TrimSpace(stdout.String()); got != buildVersion {
		t.Fatalf("got %q, want %q", got, buildVersion)
	}
}
