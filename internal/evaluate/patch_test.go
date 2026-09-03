// SPDX-License-Identifier: AGPL-3.0-or-later

package evaluate

import "testing"

func TestEvaluatePatchCurrent(t *testing.T) {
	if got := evaluatePatch("10.3.2", "10.3.2"); got != PatchCurrent {
		t.Fatalf("got %v, want current", got)
	}
}

func TestEvaluatePatchBehind(t *testing.T) {
	if got := evaluatePatch("10.3.1", "10.3.2"); got != PatchBehind {
		t.Fatalf("got %v, want behind", got)
	}
}

func TestEvaluatePatchAhead(t *testing.T) {
	// A release candidate or calendar lag: the installed build is newer
	// than what the calendar currently lists as latest. Not exotic (D6).
	if got := evaluatePatch("10.3.3", "10.3.2"); got != PatchAhead {
		t.Fatalf("got %v, want ahead", got)
	}
}

func TestEvaluatePatchCleansLatestPrefix(t *testing.T) {
	// The GitHub fallback's "latest" is a raw tag like "v2.9.0".
	if got := evaluatePatch("2.9.0", "v2.9.0"); got != PatchCurrent {
		t.Fatalf("got %v, want current after cleaning the v-prefix", got)
	}
}

func TestEvaluatePatchUnknownWhenUnparseable(t *testing.T) {
	if got := evaluatePatch("not-a-version", "10.3.2"); got != PatchUnknown {
		t.Fatalf("got %v, want unknown", got)
	}
	if got := evaluatePatch("10.3.2", ""); got != PatchUnknown {
		t.Fatalf("got %v, want unknown for an empty latest", got)
	}
}
