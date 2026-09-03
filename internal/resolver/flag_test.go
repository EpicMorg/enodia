// SPDX-License-Identifier: AGPL-3.0-or-later

package resolver

import (
	"encoding/json"
	"testing"
	"time"
)

func TestFlagUnmarshalTrue(t *testing.T) {
	var f Flag
	if err := json.Unmarshal([]byte("true"), &f); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !f.Bool || f.IsDate {
		t.Fatalf("got %+v, want Bool=true, IsDate=false", f)
	}
}

func TestFlagUnmarshalFalse(t *testing.T) {
	var f Flag
	if err := json.Unmarshal([]byte("false"), &f); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Bool || f.IsDate {
		t.Fatalf("got %+v, want Bool=false, IsDate=false", f)
	}
}

func TestFlagUnmarshalDate(t *testing.T) {
	var f Flag
	if err := json.Unmarshal([]byte(`"2026-10-28"`), &f); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !f.IsDate || !f.Bool {
		t.Fatalf("got %+v, want IsDate=true, Bool=true", f)
	}
	want := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	if !f.Date.Equal(want) {
		t.Fatalf("got date %v, want %v", f.Date, want)
	}
}

func TestFlagUnmarshalInvalid(t *testing.T) {
	var f Flag
	if err := json.Unmarshal([]byte(`"not-a-date"`), &f); err == nil {
		t.Fatal("expected an error for a string that is neither a bool nor a date")
	}
	if err := json.Unmarshal([]byte(`42`), &f); err == nil {
		t.Fatal("expected an error for a number")
	}
}

func TestDateUnmarshal(t *testing.T) {
	var d Date
	if err := json.Unmarshal([]byte(`"2025-01-22"`), &d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Date(2025, 1, 22, 0, 0, 0, 0, time.UTC)
	if !d.Equal(want) {
		t.Fatalf("got %v, want %v", d.Time, want)
	}
}

func TestDateUnmarshalInvalid(t *testing.T) {
	var d Date
	if err := json.Unmarshal([]byte(`"01/22/2025"`), &d); err == nil {
		t.Fatal("expected an error for a non-ISO date")
	}
}
