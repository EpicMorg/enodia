// SPDX-License-Identifier: AGPL-3.0-or-later

package resolver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func loadFixture(t *testing.T, name string) []Cycle {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var cycles []Cycle
	if err := json.Unmarshal(raw, &cycles); err != nil {
		t.Fatalf("parsing fixture %s: %v", name, err)
	}
	return cycles
}

// jira-software.sample.json exercises the common case: eol is always a
// date, lts is a bool.
func TestParseJiraSoftwareFixture(t *testing.T) {
	cycles := loadFixture(t, "jira-software.sample.json")
	if len(cycles) != 4 {
		t.Fatalf("got %d cycles, want 4", len(cycles))
	}
	c := cycles[0]
	if c.Cycle != "11.3" || c.Latest != "11.3.11" {
		t.Fatalf("got %+v", c)
	}
	if c.LTS == nil || !c.LTS.Bool || c.LTS.IsDate {
		t.Fatalf("lts: got %+v, want Bool=true, IsDate=false", c.LTS)
	}
	if c.EOL == nil || !c.EOL.IsDate {
		t.Fatalf("eol: got %+v, want a date", c.EOL)
	}
	if got, want := c.EOL.Date.Format(dateLayout), "2027-12-03"; got != want {
		t.Fatalf("eol date: got %q, want %q", got, want)
	}
	if c.ReleaseDate == nil || c.ReleaseDate.Format(dateLayout) != "2025-12-03" {
		t.Fatalf("releaseDate: got %+v", c.ReleaseDate)
	}
}

// redis.sample.json exercises eol:false and support:true — active support
// with no announced end date on either axis.
func TestParseRedisFixtureEOLFalseSupportTrue(t *testing.T) {
	cycles := loadFixture(t, "redis.sample.json")
	c := cycles[0]
	if c.EOL == nil || c.EOL.IsDate || c.EOL.Bool {
		t.Fatalf("eol: got %+v, want Bool=false, IsDate=false", c.EOL)
	}
	if c.Support == nil || c.Support.IsDate || !c.Support.Bool {
		t.Fatalf("support: got %+v, want Bool=true, IsDate=false", c.Support)
	}

	// The second entry has support as a date instead of true.
	c2 := cycles[1]
	if c2.Support == nil || !c2.Support.IsDate {
		t.Fatalf("support: got %+v, want a date", c2.Support)
	}
}

// nodejs.sample.json exercises lts as a date rather than a bool — the date
// marks when that release line became LTS.
func TestParseNodejsFixtureLTSAsDate(t *testing.T) {
	cycles := loadFixture(t, "nodejs.sample.json")
	c := cycles[0]
	if c.LTS == nil || !c.LTS.IsDate {
		t.Fatalf("lts: got %+v, want a date", c.LTS)
	}
	if got, want := c.LTS.Date.Format(dateLayout), "2026-10-28"; got != want {
		t.Fatalf("lts date: got %q, want %q", got, want)
	}

	// The second entry uses a plain bool instead.
	c2 := cycles[1]
	if c2.LTS == nil || c2.LTS.Bool || c2.LTS.IsDate {
		t.Fatalf("lts: got %+v, want Bool=false, IsDate=false", c2.LTS)
	}
}

// ubuntu.sample.json exercises fields this package does not model
// (codename, extendedSupport) alongside the ones it does; those extras must
// not break parsing.
func TestParseUbuntuFixtureIgnoresUnknownFields(t *testing.T) {
	cycles := loadFixture(t, "ubuntu.sample.json")
	c := cycles[0]
	if c.LTS == nil || !c.LTS.Bool || c.LTS.IsDate {
		t.Fatalf("lts: got %+v, want Bool=true, IsDate=false", c.LTS)
	}
	if c.Support == nil || !c.Support.IsDate {
		t.Fatalf("support: got %+v, want a date", c.Support)
	}
}
