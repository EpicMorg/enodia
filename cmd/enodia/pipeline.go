// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/EpicMorg/enodia/internal/collect"
	"github.com/EpicMorg/enodia/internal/config"
	"github.com/EpicMorg/enodia/internal/evaluate"
	"github.com/EpicMorg/enodia/internal/inventory"
	"github.com/EpicMorg/enodia/internal/probe"
	"github.com/EpicMorg/enodia/internal/render"
	"github.com/EpicMorg/enodia/internal/resolver"
)

// warnPrinter adapts the Warn(string) callback shape used across
// internal/config, internal/resolver and (via targetWarnPrinter)
// internal/collect to one command's stderr.
func warnPrinter(cmd *cobra.Command) func(string) {
	return func(msg string) { fmt.Fprintln(cmd.ErrOrStderr(), "warning:", msg) }
}

func targetWarnPrinter(cmd *cobra.Command) func(probe.Target, string) {
	w := warnPrinter(cmd)
	return func(t probe.Target, msg string) { w(t.ID + ": " + msg) }
}

// collectObservations loads the config from --config and probes every
// target. Shared by `collect` (which just writes the result) and
// loadInventory (which wraps it in an inventory.File for `check`/`export`).
func collectObservations(ctx context.Context, cmd *cobra.Command) (*config.Config, []probe.Observation, error) {
	path, err := config.Locate(configFlag)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, nil, err
	}
	targets, err := cfg.Build(warnPrinter(cmd))
	if err != nil {
		return nil, nil, err
	}

	observations := collect.Run(ctx, targets, collect.Options{
		Concurrency: cfg.Defaults.Concurrency,
		Retries:     cfg.Defaults.Retries,
		Backoff:     time.Duration(cfg.Defaults.Backoff),
		Warn:        targetWarnPrinter(cmd),
	})
	return cfg, observations, nil
}

// loadInventory returns the inventory to assess: read from fromPath if set,
// otherwise a fresh collect run. Per D4, the no-`--from` path is the same
// two phases (collect, then evaluate) composed in one process, not a second
// code path.
func loadInventory(ctx context.Context, cmd *cobra.Command, fromPath string) (*inventory.File, error) {
	if fromPath != "" {
		f, err := os.Open(fromPath)
		if err != nil {
			return nil, fmt.Errorf("opening %s: %w", fromPath, err)
		}
		defer f.Close()
		return inventory.Read(f)
	}

	_, observations, err := collectObservations(ctx, cmd)
	if err != nil {
		return nil, err
	}
	return &inventory.File{
		Header: inventory.Header{
			Kind:          "inventory",
			SchemaVersion: inventory.SchemaVersion,
			CollectedAt:   time.Now().UTC(),
			Tool:          "enodia/" + buildVersion,
		},
		Observations: observations,
	}, nil
}

// newLiveResolver builds the resolver check/export use against the real
// lifecycle data sources, with an on-disk cache when one is available.
//
// check and export call through the buildResolver variable rather than this
// function directly, so tests can substitute a resolver wired to a fake
// Source instead of the real endoflife.date/GitHub endpoints.
var buildResolver = newLiveResolver

func newLiveResolver(cmd *cobra.Command) *resolver.Resolver {
	var cache *resolver.Cache
	if dir, err := resolver.DefaultCacheDir(); err == nil {
		cache = &resolver.Cache{Dir: dir, TTL: 24 * time.Hour}
	} else {
		warnPrinter(cmd)(fmt.Sprintf("lifecycle cache disabled: %v", err))
	}
	res := resolver.New(cache)
	res.Warn = warnPrinter(cmd)
	return res
}

// assess evaluates every observation in inv against its product's lifecycle
// calendar (via res), per policy, as of inv's own collection time — D8
// forbids reaching for time.Now() here.
func assess(ctx context.Context, inv *inventory.File, policy evaluate.Policy, res *resolver.Resolver) []evaluate.Assessment {
	asOf := inv.Header.CollectedAt
	out := make([]evaluate.Assessment, 0, len(inv.Observations))
	for _, o := range inv.Observations {
		var ref probe.ResolverRef
		if p, err := probe.Get(o.Product); err == nil {
			ref = p.Meta().DefaultResolver
		}

		var cycles []resolver.Cycle
		var resolveErr error
		if ref.Type != "" {
			cycles, resolveErr = res.Resolve(ctx, ref)
		}

		out = append(out, evaluate.Evaluate(evaluate.Input{
			Observation: o,
			Resolver:    ref,
			Cycles:      cycles,
			ResolveErr:  resolveErr,
		}, asOf, policy))
	}
	return out
}

// worstSeverity is the max OverallSeverity across every assessment.
func worstSeverity(assessments []evaluate.Assessment) evaluate.Severity {
	worst := evaluate.SeverityNone
	for _, a := range assessments {
		worst = evaluate.Max(worst, a.OverallSeverity())
	}
	return worst
}

// buildReport wraps an evaluated inventory as the input every internal/render
// output function shares.
func buildReport(inv *inventory.File, assessments []evaluate.Assessment) render.Report {
	return render.Report{
		GeneratedAt:  time.Now().UTC(),
		AsOf:         inv.Header.CollectedAt,
		Tool:         "enodia/" + buildVersion,
		Observations: inv.Observations,
		Assessments:  assessments,
	}
}

// severityExitCode maps a worst-case severity onto the exit codes
// docs/ROADMAP.md reserves for policy findings ("3+"), kept clear of 1
// (internal error) and 2 (bad arguments).
func severityExitCode(s evaluate.Severity) int {
	switch s {
	case evaluate.SeverityFail:
		return 4
	case evaluate.SeverityWarn, evaluate.SeverityInfo:
		return 3
	default:
		return 0
	}
}
