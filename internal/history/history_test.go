// SPDX-License-Identifier: AGPL-3.0-or-later

package history

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/EpicMorg/enodia/internal/evaluate"
	"github.com/EpicMorg/enodia/internal/probe"
	"github.com/EpicMorg/enodia/internal/resolver"
)

func writeInventory(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadDirSortsByCollectedAt(t *testing.T) {
	dir := t.TempDir()
	// Written newest-first, on purpose, to prove LoadDir sorts rather than
	// just reflecting directory-listing order.
	writeInventory(t, dir, "b.jsonl", `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-02T00:00:00Z","tool":"test"}
`)
	writeInventory(t, dir, "a.jsonl", `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
`)

	files, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("got %d files, want 2", len(files))
	}
	if !files[0].Header.CollectedAt.Before(files[1].Header.CollectedAt) {
		t.Fatalf("got %v then %v, want oldest first", files[0].Header.CollectedAt, files[1].Header.CollectedAt)
	}
}

func TestLoadDirIgnoresNonJSONLFiles(t *testing.T) {
	dir := t.TempDir()
	writeInventory(t, dir, "a.jsonl", `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
`)
	writeInventory(t, dir, "README.md", "not an inventory")
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}

	files, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1 (README.md and subdir/ must be ignored)", len(files))
	}
}

func TestLoadDirEmptyDirectoryErrors(t *testing.T) {
	if _, err := LoadDir(t.TempDir()); err == nil {
		t.Fatal("expected an error for a directory with no *.jsonl files")
	}
}

func TestLoadDirMissingDirectoryErrors(t *testing.T) {
	if _, err := LoadDir(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected an error for a nonexistent directory")
	}
}

func TestLoadDirPropagatesParseErrors(t *testing.T) {
	dir := t.TempDir()
	writeInventory(t, dir, "bad.jsonl", "not valid jsonl at all")
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("expected an error for an unparseable inventory")
	}
}

func TestBuildGroupsByIDAndOrdersPointsByAsOf(t *testing.T) {
	dir := t.TempDir()
	writeInventory(t, dir, "day1.jsonl", `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"generic","version":"1.0","normalized":"1.0","collectedAt":"2026-01-01T00:00:00Z"}
`)
	writeInventory(t, dir, "day2.jsonl", `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-02T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"generic","version":"1.1","normalized":"1.1","collectedAt":"2026-01-02T00:00:00Z"}
`)
	files, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	timelines := Build(context.Background(), files, &resolver.Resolver{}, evaluate.Policy{})
	if len(timelines) != 1 {
		t.Fatalf("got %d timelines, want 1", len(timelines))
	}
	tl := timelines[0]
	if tl.ID != "x" || len(tl.Points) != 2 {
		t.Fatalf("got %+v", tl)
	}
	if tl.Points[0].Version != "1.0" || tl.Points[1].Version != "1.1" {
		t.Fatalf("got versions %q then %q, want oldest first", tl.Points[0].Version, tl.Points[1].Version)
	}
	if !tl.Points[0].AsOf.Before(tl.Points[1].AsOf) {
		t.Fatalf("points not ordered by asOf: %v then %v", tl.Points[0].AsOf, tl.Points[1].AsOf)
	}
}

func TestBuildTimelinesAreSortedByID(t *testing.T) {
	dir := t.TempDir()
	writeInventory(t, dir, "day1.jsonl", `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"zeta","product":"generic","version":"1.0","normalized":"1.0","collectedAt":"2026-01-01T00:00:00Z"}
{"kind":"observation","id":"alpha","product":"generic","version":"1.0","normalized":"1.0","collectedAt":"2026-01-01T00:00:00Z"}
`)
	files, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	timelines := Build(context.Background(), files, &resolver.Resolver{}, evaluate.Policy{})
	if len(timelines) != 2 || timelines[0].ID != "alpha" || timelines[1].ID != "zeta" {
		t.Fatalf("got %+v, want alpha before zeta", timelines)
	}
}

func TestBuildUsesEachFilesOwnAsOfForEvaluation(t *testing.T) {
	dir := t.TempDir()
	// A cycle that goes EOL between day1 and day2 — the point recorded on
	// day1 must read active, and the one on day2 must read eol, proving
	// each point is evaluated against its own file's asOf, not "now" or a
	// single shared asOf.
	writeInventory(t, dir, "day1.jsonl", `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"jira","version":"10.3.1","normalized":"10.3.1","collectedAt":"2026-01-01T00:00:00Z"}
`)
	writeInventory(t, dir, "day2.jsonl", `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-06-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"jira","version":"10.3.1","normalized":"10.3.1","collectedAt":"2026-06-01T00:00:00Z"}
`)
	files, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	res := &resolver.Resolver{
		Sources: map[string]resolver.Source{
			"endoflife": fakeSource{cycles: []resolver.Cycle{
				{Cycle: "10.3", Latest: "10.3.2", EOL: dateFlag("2026-03-01")},
			}},
		},
	}
	timelines := Build(context.Background(), files, res, evaluate.Policy{})
	if len(timelines) != 1 || len(timelines[0].Points) != 2 {
		t.Fatalf("got %+v", timelines)
	}
	if timelines[0].Points[0].Assessment.Lifecycle != evaluate.LifecycleActive {
		t.Fatalf("day1: got %v, want active", timelines[0].Points[0].Assessment.Lifecycle)
	}
	if timelines[0].Points[1].Assessment.Lifecycle != evaluate.LifecycleEOL {
		t.Fatalf("day2: got %v, want eol", timelines[0].Points[1].Assessment.Lifecycle)
	}
}

func TestBuildNoResolverForProductWithoutOne(t *testing.T) {
	dir := t.TempDir()
	writeInventory(t, dir, "day1.jsonl", `{"kind":"inventory","schemaVersion":1,"collectedAt":"2026-01-01T00:00:00Z","tool":"test"}
{"kind":"observation","id":"x","product":"generic","version":"1.0","normalized":"1.0","collectedAt":"2026-01-01T00:00:00Z"}
`)
	files, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	timelines := Build(context.Background(), files, &resolver.Resolver{}, evaluate.Policy{})
	if timelines[0].Points[0].Assessment.Reason != evaluate.ReasonNoResolver {
		t.Fatalf("got %+v", timelines[0].Points[0].Assessment)
	}
}

// fakeSource and dateFlag mirror the same-named helpers used throughout
// internal/resolver's and internal/evaluate's own tests.
type fakeSource struct {
	cycles []resolver.Cycle
	err    error
}

func (s fakeSource) Fetch(context.Context, probe.ResolverRef) ([]resolver.Cycle, error) {
	return s.cycles, s.err
}

func dateFlag(s string) *resolver.Flag {
	tm, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return &resolver.Flag{Bool: true, IsDate: true, Date: tm}
}
