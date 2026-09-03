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
	got := strings.TrimSpace(stdout.String())
	for _, want := range []string{buildVersion, buildCommit, buildDate} {
		if !strings.Contains(got, want) {
			t.Fatalf("got %q, want it to contain %q", got, want)
		}
	}
}
