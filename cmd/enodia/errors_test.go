// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"testing"
)

func TestExitErrorMessage(t *testing.T) {
	e := &ExitError{Code: 1, Err: errors.New("boom")}
	if e.Error() != "boom" {
		t.Fatalf("got %q, want %q", e.Error(), "boom")
	}
}

func TestExitErrorNilErrHasEmptyMessage(t *testing.T) {
	e := &ExitError{Code: 3}
	if e.Error() != "" {
		t.Fatalf("got %q, want empty", e.Error())
	}
}

func TestExitErrorUnwraps(t *testing.T) {
	inner := errors.New("inner")
	e := &ExitError{Code: 1, Err: inner}
	if !errors.Is(e, inner) {
		t.Fatal("expected errors.Is to see through to the wrapped error")
	}
}

func TestExitCodeNilIsZero(t *testing.T) {
	if got := exitCode(nil); got != 0 {
		t.Fatalf("got %d, want 0", got)
	}
}

func TestExitCodeUsesExitErrorCode(t *testing.T) {
	if got := exitCode(&ExitError{Code: 4}); got != 4 {
		t.Fatalf("got %d, want 4", got)
	}
}

func TestExitCodeWrappedExitError(t *testing.T) {
	err := fmt.Errorf("context: %w", &ExitError{Code: 3})
	if got := exitCode(err); got != 3 {
		t.Fatalf("got %d, want 3 (errors.As must see through the wrapping)", got)
	}
}

func TestExitCodePlainErrorIsBadArguments(t *testing.T) {
	if got := exitCode(errors.New("unknown flag")); got != 2 {
		t.Fatalf("got %d, want 2 (a plain error only ever comes from cobra itself)", got)
	}
}
