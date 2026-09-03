// SPDX-License-Identifier: AGPL-3.0-or-later

// Package render turns a set of observations and assessments into the
// formats a human or a monitoring pipeline actually consumes: a terminal
// table with a few different focuses, JSON, a Prometheus textfile, and one
// self-contained HTML file.
//
// Nothing here computes a verdict — per D7, that already happened in
// internal/evaluate. Render only formats what it's given, and per D14 it
// never serves anything itself: export writes one file, and something else
// (nginx, a cron job) is responsible for the rest.
package render

import (
	"fmt"
	"io"
	"time"

	"github.com/EpicMorg/enodia/internal/evaluate"
	"github.com/EpicMorg/enodia/internal/probe"
)

// Report bundles everything a renderer needs. Observations carries raw
// facts even where an Assessment has nothing to say about them — a product
// with no lifecycle calendar still belongs in the fleet view.
type Report struct {
	GeneratedAt  time.Time             `json:"generatedAt"`
	AsOf         time.Time             `json:"asOf"`
	Tool         string                `json:"tool,omitempty"`
	Observations []probe.Observation   `json:"observations,omitempty"`
	Assessments  []evaluate.Assessment `json:"assessments,omitempty"`
}

// View selects which table focus Table renders.
type View string

const (
	// ViewCompact is one row per target: the axes, severity and reason.
	// It's also what Table renders when view is empty.
	ViewCompact View = "compact"
	// ViewLifecycle focuses on lifecycle boundaries: eol/support dates and
	// how many days remain as of the report's AsOf.
	ViewLifecycle View = "lifecycle"
	// ViewDrift focuses on the patch axis: installed vs. latest-in-cycle.
	ViewDrift View = "drift"
	// ViewFleet groups by product and version to show the spread across
	// instances — the offline-only feature: it needs nothing but the
	// inventory itself, no lifecycle resolver at all.
	ViewFleet View = "fleet"
)

// errWriter lets a renderer make many small writes without checking each
// one: the first error sticks, and every write after it is a no-op.
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) printf(format string, args ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, args...)
}

// formatDate renders a *time.Time as a plain calendar date, or "-" when nil.
func formatDate(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Format("2006-01-02")
}

// daysUntil is the whole number of days from asOf to t, or "-" when t is
// nil. A negative number means t is in the past.
func daysUntil(t *time.Time, asOf time.Time) string {
	if t == nil {
		return "-"
	}
	return fmt.Sprintf("%d", int(t.Sub(asOf).Hours()/24))
}

// firstNonEmpty returns the first non-empty string, or the last argument
// (conventionally a placeholder like "-") if all the rest are empty.
func firstNonEmpty(values ...string) string {
	for _, v := range values[:len(values)-1] {
		if v != "" {
			return v
		}
	}
	return values[len(values)-1]
}

// indexObservations maps observation ID to the observation itself, for
// views that need to join Assessments back to what was actually observed.
func indexObservations(obs []probe.Observation) map[string]probe.Observation {
	m := make(map[string]probe.Observation, len(obs))
	for _, o := range obs {
		m[o.ID] = o
	}
	return m
}
