// SPDX-License-Identifier: AGPL-3.0-or-later

// Package history builds a per-target assessment timeline from a directory
// of dated inventories.
//
// docs/ROADMAP.md's own words: "a directory of dated inventories is already
// most of it" — D5's format (self-contained JSON Lines, one header, no
// external state) is exactly what a directory of `enodia collect -o
// "$(date +%F).jsonl"` runs already produces, for free, with no code
// needed on the writing side. This package is the other half: reading many
// of them back as one history instead of one snapshot at a time.
package history

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/EpicMorg/enodia/internal/evaluate"
	"github.com/EpicMorg/enodia/internal/inventory"
	"github.com/EpicMorg/enodia/internal/probe"
	"github.com/EpicMorg/enodia/internal/render"
	"github.com/EpicMorg/enodia/internal/resolver"
)

// LoadDir reads every "*.jsonl" file directly inside dir as an inventory
// (not recursive), sorted oldest first by each file's own CollectedAt — the
// order a timeline needs, and D8-consistent: each file's collection time
// comes from the file itself, not from the file's mtime or name.
func LoadDir(dir string) ([]*inventory.File, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}

	var files []*inventory.File
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		inv, err := loadOne(path)
		if err != nil {
			return nil, err
		}
		files = append(files, inv)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no *.jsonl inventories found in %s", dir)
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Header.CollectedAt.Before(files[j].Header.CollectedAt)
	})
	return files, nil
}

func loadOne(path string) (*inventory.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()
	inv, err := inventory.Read(f)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return inv, nil
}

// Build evaluates every observation in every file against that file's own
// asOf — D8 forbids reaching for time.Now() here, the same as any other
// evaluation — and groups the results into one Timeline per target ID,
// oldest point first, timelines sorted by ID.
//
// res is expected to carry an on-disk cache (see internal/resolver): the
// same product recurring across many dated files is the norm, not the
// exception, and refetching its lifecycle calendar once per file would
// undo exactly the caching resolver.Cache exists for.
func Build(ctx context.Context, files []*inventory.File, res *resolver.Resolver, policy evaluate.Policy) []render.Timeline {
	byID := make(map[string]*render.Timeline)
	var order []string

	for _, f := range files {
		asOf := f.Header.CollectedAt
		for _, o := range f.Observations {
			tl, ok := byID[o.ID]
			if !ok {
				tl = &render.Timeline{ID: o.ID, Product: o.Product}
				byID[o.ID] = tl
				order = append(order, o.ID)
			}

			var ref probe.ResolverRef
			if p, err := probe.Get(o.Product); err == nil {
				ref = p.Meta().DefaultResolver
			}
			var cycles []resolver.Cycle
			var resolveErr error
			if ref.Type != "" {
				cycles, resolveErr = res.Resolve(ctx, ref)
			}

			a := evaluate.Evaluate(evaluate.Input{
				Observation: o,
				Resolver:    ref,
				Cycles:      cycles,
				ResolveErr:  resolveErr,
			}, asOf, policy)

			version := o.Normalized
			if version == "" {
				version = o.Version
			}
			tl.Points = append(tl.Points, render.TimelinePoint{
				AsOf: asOf, Version: version, Assessment: a,
			})
		}
	}

	sort.Strings(order)
	timelines := make([]render.Timeline, 0, len(order))
	for _, id := range order {
		timelines = append(timelines, *byID[id])
	}
	return timelines
}
