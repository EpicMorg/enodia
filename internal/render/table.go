// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Table writes one of the four views as an aligned text table. An empty
// view renders ViewCompact.
func Table(w io.Writer, view View, r Report) error {
	headers, rows, err := viewRows(view, r)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(headers, "\t"))
	for _, row := range rows {
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	return tw.Flush()
}

// viewRows dispatches to the one view function that knows how to build
// view's rows. HTML uses this too, so the text table and the HTML report
// can never show different data for the same view.
func viewRows(view View, r Report) (headers []string, rows [][]string, err error) {
	switch view {
	case ViewCompact, "":
		h, rw := compactRows(r)
		return h, rw, nil
	case ViewLifecycle:
		h, rw := lifecycleRows(r)
		return h, rw, nil
	case ViewDrift:
		h, rw := driftRows(r)
		return h, rw, nil
	case ViewFleet:
		h, rw := fleetRows(r)
		return h, rw, nil
	default:
		return nil, nil, fmt.Errorf("unknown view %q", view)
	}
}
