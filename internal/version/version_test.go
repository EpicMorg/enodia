// SPDX-License-Identifier: AGPL-3.0-or-later

package version

import "testing"

func TestClean(t *testing.T) {
	cases := map[string]string{
		"10.3.2":                 "10.3.2",
		"v9.4.1":                 "9.4.1",
		"17.8.1-ee":              "17.8.1",
		"2025.03.1 (build 4711)": "2025.03.1",
		"1.1.1w":                 "1.1.1w",
		"  8.19.4  ":             "8.19.4",
	}
	for in, want := range cases {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"10.3.2", "10.3.1", 1},
		{"10.3", "10.3.0", 0},
		{"9.12.0", "9.4.0", 1},       // not a string comparison
		{"2025.03.1", "2025.3.1", 0}, // leading zeros are cosmetic
		{"17.8.1-ee", "17.8.1", 0},
	}
	for _, c := range cases {
		got, ok := Compare(c.a, c.b)
		if !ok {
			t.Fatalf("Compare(%q,%q) not comparable", c.a, c.b)
		}
		if got != c.want {
			t.Errorf("Compare(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	if _, ok := Compare("", "1.0"); ok {
		t.Error("empty input must not compare")
	}
}

// The bug a naive strings.HasPrefix would introduce.
func TestInCycleIsNotAPrefixMatch(t *testing.T) {
	if InCycle("10.30.1", "10.3") {
		t.Error("10.30.1 must not fall inside branch 10.3")
	}
	if !InCycle("10.3.2", "10.3") {
		t.Error("10.3.2 belongs to branch 10.3")
	}
	if !InCycle("2025.03.1", "2025.03") {
		t.Error("TeamCity-style branches must match")
	}
	if InCycle("10.3", "10.3.2") {
		t.Error("a branch cannot be longer than the version")
	}
}

func TestMatchCyclePicksMostSpecific(t *testing.T) {
	got, ok := MatchCycle("10.3.2", []string{"11", "10", "10.3", "9.12"})
	if !ok || got != "10.3" {
		t.Errorf("MatchCycle = %q (%v), want 10.3", got, ok)
	}
	if _, ok := MatchCycle("7.1.0", []string{"10", "9"}); ok {
		t.Error("a version outside every published branch must not match")
	}
}

func TestEdition(t *testing.T) {
	if got := Edition("17.8.1-ee"); got != "ee" {
		t.Errorf("Edition = %q, want ee", got)
	}
	if got := Edition("10.3.2"); got != "" {
		t.Errorf("Edition = %q, want empty", got)
	}
}
