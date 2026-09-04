// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/EpicMorg/enodia/internal/evaluate"
)

// TimelinePoint is one dated inventory's assessment for a single target.
type TimelinePoint struct {
	AsOf       time.Time           `json:"asOf"`
	Version    string              `json:"version,omitempty"`
	Assessment evaluate.Assessment `json:"assessment"`
}

// Timeline is one target's history across a directory of dated
// inventories, oldest point first.
type Timeline struct {
	ID      string          `json:"id"`
	Product string          `json:"product,omitempty"`
	Points  []TimelinePoint `json:"points"`
}

// HistoryReport bundles every target's timeline — docs/ROADMAP.md's
// "historical tracking": internal/history builds this from a directory of
// dated inventories (D5's format already gives you that directory for
// free); this package only formats it.
type HistoryReport struct {
	GeneratedAt time.Time  `json:"generatedAt"`
	Tool        string     `json:"tool,omitempty"`
	Timelines   []Timeline `json:"timelines"`
}

// HistoryTable writes one row per (target, snapshot) pair, oldest first
// within each target, so scanning down the table shows exactly when
// something changed.
func HistoryTable(w io.Writer, r HistoryReport) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join([]string{"ID", "DATE", "VERSION", "PATCH", "LIFECYCLE", "BRANCH", "SEVERITY"}, "\t"))
	for _, tl := range r.Timelines {
		for _, p := range tl.Points {
			row := []string{
				tl.ID,
				p.AsOf.Format("2006-01-02"),
				firstNonEmpty(p.Version, "-"),
				string(p.Assessment.Patch),
				string(p.Assessment.Lifecycle),
				string(p.Assessment.Branch),
				string(p.Assessment.OverallSeverity()),
			}
			fmt.Fprintln(tw, strings.Join(row, "\t"))
		}
	}
	return tw.Flush()
}

// HistoryJSON writes the full report as indented JSON.
func HistoryJSON(w io.Writer, r HistoryReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
