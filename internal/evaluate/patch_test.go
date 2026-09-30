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

// A real, patched vCenter/ESXi 8.0 host used to compare "ahead" of
// endoflife.date's own "8.0 U3k"/"8.0 Update 3k" latest — the space before
// the update letter made version.Clean's first-field split read it as bare
// "8.0", losing the update number entirely. See internal/version's
// reVMwareUpdate.
func TestEvaluatePatchFoldsVMwareUpdateLetter(t *testing.T) {
	if got := evaluatePatch("8.0.3", "8.0 U3k"); got != PatchCurrent {
		t.Fatalf("got %v, want current (Update 3 == .3)", got)
	}
	if got := evaluatePatch("8.0.3", "8.0 Update 3k"); got != PatchCurrent {
		t.Fatalf("got %v, want current (Update 3 == .3)", got)
	}
	if got := evaluatePatch("8.0.2", "8.0 Update 3k"); got != PatchBehind {
		t.Fatalf("got %v, want behind (Update 2 predates Update 3)", got)
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
