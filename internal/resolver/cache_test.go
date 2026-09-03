// SPDX-License-Identifier: AGPL-3.0-or-later

package resolver

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/EpicMorg/enodia/internal/probe"
)

func TestCacheMissWhenNoEntry(t *testing.T) {
	c := Cache{Dir: t.TempDir(), TTL: time.Hour}
	_, hit, err := c.Load(probe.ResolverRef{Type: "endoflife", ID: "jira-software"}, time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit {
		t.Fatal("expected a miss for an entry that was never stored")
	}
}

func TestCacheStoreThenLoadRoundTrips(t *testing.T) {
	c := Cache{Dir: t.TempDir(), TTL: time.Hour}
	ref := probe.ResolverRef{Type: "endoflife", ID: "jira-software"}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	want := []Cycle{{Cycle: "10.3", Latest: "10.3.2"}}

	if err := c.Store(ref, want, now); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, hit, err := c.Load(ref, now)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !hit {
		t.Fatal("expected a hit right after Store")
	}
	if len(got) != 1 || got[0].Cycle != "10.3" || got[0].Latest != "10.3.2" {
		t.Fatalf("got %+v", got)
	}
}

// TestCacheRoundTripsDateAndFlagFields is a regression test: an earlier
// version of Date/Flag had no MarshalJSON, so Store serialized their dates
// via time.Time's default RFC3339 encoding while Load's UnmarshalJSON only
// ever accepted YYYY-MM-DD — any cached cycle with a release date or an
// eol/support/lts date failed to load back at all.
func TestCacheRoundTripsDateAndFlagFields(t *testing.T) {
	c := Cache{Dir: t.TempDir(), TTL: time.Hour}
	ref := probe.ResolverRef{Type: "endoflife", ID: "jira-software"}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	want := []Cycle{{
		Cycle:             "10.3",
		Latest:            "10.3.2",
		ReleaseDate:       &Date{Time: time.Date(2024, 12, 5, 0, 0, 0, 0, time.UTC)},
		LatestReleaseDate: &Date{Time: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)},
		EOL:               &Flag{Bool: true, IsDate: true, Date: time.Date(2026, 12, 5, 0, 0, 0, 0, time.UTC)},
		Support:           &Flag{Bool: true},
		LTS:               &Flag{Bool: false},
	}}

	if err := c.Store(ref, want, now); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, hit, err := c.Load(ref, now)
	if err != nil {
		t.Fatalf("Load: %v (this is the exact failure mode of the MarshalJSON regression)", err)
	}
	if !hit {
		t.Fatal("expected a hit right after Store")
	}
	if len(got) != 1 {
		t.Fatalf("got %d cycles, want 1", len(got))
	}
	c0 := got[0]
	if c0.ReleaseDate == nil || !c0.ReleaseDate.Equal(want[0].ReleaseDate.Time) {
		t.Fatalf("ReleaseDate: got %v, want %v", c0.ReleaseDate, want[0].ReleaseDate)
	}
	if c0.EOL == nil || !c0.EOL.IsDate || !c0.EOL.Date.Equal(want[0].EOL.Date) {
		t.Fatalf("EOL: got %+v, want %+v", c0.EOL, want[0].EOL)
	}
	if c0.Support == nil || c0.Support.IsDate || !c0.Support.Bool {
		t.Fatalf("Support: got %+v, want Bool=true, IsDate=false", c0.Support)
	}
	if c0.LTS == nil || c0.LTS.Bool {
		t.Fatalf("LTS: got %+v, want Bool=false", c0.LTS)
	}
}

func TestCacheEntryExpiresAfterTTL(t *testing.T) {
	c := Cache{Dir: t.TempDir(), TTL: time.Hour}
	ref := probe.ResolverRef{Type: "endoflife", ID: "jira-software"}
	fetchedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := c.Store(ref, []Cycle{{Cycle: "10.3"}}, fetchedAt); err != nil {
		t.Fatalf("Store: %v", err)
	}

	justBeforeExpiry := fetchedAt.Add(59 * time.Minute)
	if _, hit, err := c.Load(ref, justBeforeExpiry); err != nil || !hit {
		t.Fatalf("expected a hit just before TTL, got hit=%v err=%v", hit, err)
	}

	justAfterExpiry := fetchedAt.Add(61 * time.Minute)
	if _, hit, err := c.Load(ref, justAfterExpiry); err != nil || hit {
		t.Fatalf("expected a miss just after TTL, got hit=%v err=%v", hit, err)
	}
}

func TestCacheDifferentRefsDoNotCollide(t *testing.T) {
	c := Cache{Dir: t.TempDir(), TTL: time.Hour}
	now := time.Now()
	a := probe.ResolverRef{Type: "endoflife", ID: "jira-software"}
	b := probe.ResolverRef{Type: "endoflife", ID: "confluence"}

	if err := c.Store(a, []Cycle{{Cycle: "a"}}, now); err != nil {
		t.Fatalf("Store a: %v", err)
	}
	if err := c.Store(b, []Cycle{{Cycle: "b"}}, now); err != nil {
		t.Fatalf("Store b: %v", err)
	}

	gotA, _, _ := c.Load(a, now)
	gotB, _, _ := c.Load(b, now)
	if gotA[0].Cycle != "a" || gotB[0].Cycle != "b" {
		t.Fatalf("cross-contamination: a=%+v b=%+v", gotA, gotB)
	}
}

// A GitHub-style ref.ID contains a slash ("owner/repo"). The cache key must
// not turn that into an unwanted subdirectory.
func TestCacheRefIDWithSlashStaysOneFile(t *testing.T) {
	dir := t.TempDir()
	c := Cache{Dir: dir, TTL: time.Hour}
	ref := probe.ResolverRef{Type: "github", ID: "owner/repo"}
	now := time.Now()

	if err := c.Store(ref, []Cycle{{Cycle: "v1.0.0"}}, now); err != nil {
		t.Fatalf("Store: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].IsDir() {
		t.Fatalf("got %v, want exactly one plain file", entries)
	}

	got, hit, err := c.Load(ref, now)
	if err != nil || !hit {
		t.Fatalf("Load: hit=%v err=%v", hit, err)
	}
	if got[0].Cycle != "v1.0.0" {
		t.Fatalf("got %+v", got)
	}
}

func TestCacheLoadCorruptFileErrors(t *testing.T) {
	dir := t.TempDir()
	c := Cache{Dir: dir, TTL: time.Hour}
	ref := probe.ResolverRef{Type: "endoflife", ID: "jira-software"}

	if err := os.WriteFile(c.path(ref), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, hit, err := c.Load(ref, time.Now())
	if err == nil {
		t.Fatal("expected an error for a corrupt cache file")
	}
	if hit {
		t.Fatal("a corrupt entry must never be reported as a hit")
	}
}

func TestCacheStoreCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "cache")
	c := Cache{Dir: dir, TTL: time.Hour}
	ref := probe.ResolverRef{Type: "endoflife", ID: "jira-software"}
	if err := c.Store(ref, []Cycle{{Cycle: "1"}}, time.Now()); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("cache dir was not created: %v", err)
	}
}

func TestCacheStoreLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	c := Cache{Dir: dir, TTL: time.Hour}
	ref := probe.ResolverRef{Type: "endoflife", ID: "jira-software"}
	if err := c.Store(ref, []Cycle{{Cycle: "1"}}, time.Now()); err != nil {
		t.Fatalf("Store: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("leftover temp file: %s", e.Name())
		}
	}
}
