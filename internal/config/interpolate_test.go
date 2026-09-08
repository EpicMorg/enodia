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

func TestInterpolateSubstitutesSetVariable(t *testing.T) {
	out, err := Interpolate([]byte("token: ${TOKEN}"), lookupFrom(map[string]string{"TOKEN": "s3cret"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := string(out), "token: s3cret"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestInterpolateMultipleVariablesOneLine(t *testing.T) {
	lookup := lookupFrom(map[string]string{"HOST": "example.com", "PORT": "8443"})
	out, err := Interpolate([]byte("address: https://${HOST}:${PORT}"), lookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := string(out), "address: https://example.com:8443"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestInterpolateUnsetVariableWithoutDefaultErrors(t *testing.T) {
	_, err := Interpolate([]byte("token: ${MISSING}"), lookupFrom(nil))
	if err == nil {
		t.Fatal("expected an error for an unset variable with no default")
	}
}

func TestInterpolateUnsetVariableUsesDefault(t *testing.T) {
	out, err := Interpolate([]byte("token: ${MISSING:-fallback}"), lookupFrom(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := string(out), "token: fallback"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestInterpolateEmptyDefaultIsAllowed(t *testing.T) {
	out, err := Interpolate([]byte("token: ${MISSING:-}"), lookupFrom(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := string(out), "token: "; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestInterpolateSetButEmptyUsesDefault(t *testing.T) {
	// Shell ${VAR:-default} semantics: a set-but-empty value is treated the
	// same as unset when a default is present.
	out, err := Interpolate([]byte("token: ${TOKEN:-fallback}"), lookupFrom(map[string]string{"TOKEN": ""}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := string(out), "token: fallback"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestInterpolateSetButEmptyPassesThroughWithoutDefault(t *testing.T) {
	out, err := Interpolate([]byte("token: '${TOKEN}'"), lookupFrom(map[string]string{"TOKEN": ""}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := string(out), "token: ''"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestInterpolateSetVariablePreferredOverDefault(t *testing.T) {
	out, err := Interpolate([]byte("token: ${TOKEN:-fallback}"), lookupFrom(map[string]string{"TOKEN": "real"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := string(out), "token: real"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestInterpolateNoVariablesIsUnchanged(t *testing.T) {
	out, err := Interpolate([]byte("plain: text"), lookupFrom(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := string(out), "plain: text"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestInterpolateMalformedBraceIsLeftAlone(t *testing.T) {
	// No closing brace: not a match for the interpolation pattern at all, so
	// it passes through untouched rather than erroring.
	out, err := Interpolate([]byte("weird: ${NOPE"), lookupFrom(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := string(out), "weird: ${NOPE"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestInterpolateEnvLookupUsesProcessEnvironment(t *testing.T) {
	t.Setenv("ENODIA_TEST_VAR", "from-env")
	out, err := Interpolate([]byte("v: ${ENODIA_TEST_VAR}"), envLookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := string(out), "v: from-env"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestInterpolateErrorMentionsVariableName(t *testing.T) {
	_, err := Interpolate([]byte("v: ${SOME_MISSING_VAR}"), lookupFrom(nil))
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "SOME_MISSING_VAR") {
		t.Fatalf("error %q does not mention the missing variable", err.Error())
	}
}
