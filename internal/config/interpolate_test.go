// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"
)

func lookupFrom(env map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		v, ok := env[name]
		return v, ok
	}
}

func TestExpandSubstitutesSetVariable(t *testing.T) {
	out, err := expand("${TOKEN}", lookupFrom(map[string]string{"TOKEN": "s3cret"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := out, "s3cret"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestExpandMultipleVariablesOneScalar(t *testing.T) {
	lookup := lookupFrom(map[string]string{"HOST": "example.com", "PORT": "8443"})
	out, err := expand("https://${HOST}:${PORT}", lookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := out, "https://example.com:8443"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestExpandUnsetVariableWithoutDefaultErrors(t *testing.T) {
	_, err := expand("${MISSING}", lookupFrom(nil))
	if err == nil {
		t.Fatal("expected an error for an unset variable with no default")
	}
}

func TestExpandUnsetVariableUsesDefault(t *testing.T) {
	out, err := expand("${MISSING:-fallback}", lookupFrom(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := out, "fallback"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestExpandEmptyDefaultIsAllowed(t *testing.T) {
	out, err := expand("${MISSING:-}", lookupFrom(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := out, ""; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestExpandSetButEmptyUsesDefault(t *testing.T) {
	// Shell ${VAR:-default} semantics: a set-but-empty value is treated the
	// same as unset when a default is present.
	out, err := expand("${TOKEN:-fallback}", lookupFrom(map[string]string{"TOKEN": ""}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := out, "fallback"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestExpandSetButEmptyPassesThroughWithoutDefault(t *testing.T) {
	out, err := expand("${TOKEN}", lookupFrom(map[string]string{"TOKEN": ""}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := out, ""; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestExpandSetVariablePreferredOverDefault(t *testing.T) {
	out, err := expand("${TOKEN:-fallback}", lookupFrom(map[string]string{"TOKEN": "real"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := out, "real"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestExpandNoVariablesIsUnchanged(t *testing.T) {
	out, err := expand("plain text", lookupFrom(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := out, "plain text"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestExpandMalformedBraceIsLeftAlone(t *testing.T) {
	// No closing brace: not a match for the interpolation pattern at all, so
	// it passes through untouched rather than erroring.
	out, err := expand("${NOPE", lookupFrom(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := out, "${NOPE"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestExpandErrorMentionsVariableName(t *testing.T) {
	_, err := expand("${SOME_MISSING_VAR}", lookupFrom(nil))
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "SOME_MISSING_VAR") {
		t.Fatalf("error %q does not mention the missing variable", err.Error())
	}
}
