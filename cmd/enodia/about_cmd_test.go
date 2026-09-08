// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"
)

func TestRunAboutCmd(t *testing.T) {
	cmd, stdout, _ := testCmd(t)
	if err := runAboutCmd(cmd, nil); err != nil {
		t.Fatalf("runAboutCmd: %v", err)
	}
	got := stdout.String()

	if !strings.Contains(got, asciiLogo) {
		t.Fatalf("output missing the embedded logo:\n%s", got)
	}
	for _, want := range []string{buildVersion, buildCommit, buildDate, "AGPL-3.0-or-later", "github.com/EpicMorg/enodia"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}
