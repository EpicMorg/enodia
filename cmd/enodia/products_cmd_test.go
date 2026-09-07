// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"
)

func TestRunProductsCmdListsKnownProducts(t *testing.T) {
	cmd, stdout, _ := testCmd(t)
	if err := runProductsCmd(cmd, nil); err != nil {
		t.Fatalf("runProductsCmd: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"jira", "confluence", "generic"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing product %q:\n%s", want, out)
		}
	}
}
