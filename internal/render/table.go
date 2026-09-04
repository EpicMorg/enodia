// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Table writes one of the four views as an aligned text table. An empty
// view renders ViewCompact. Row tones are ignored here — plain text has no
// color; CDN-mode HTML is the one renderer that uses them.
func Table(w io.Writer, view View, r Report) error {
	headers, rows, _, err := viewRows(view, r)
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
func viewRows(view View, r Report) (headers []string, rows [][]string, tones []RowTone, err error) {
	switch view {
	case ViewCompact, "":
		h, rw, t := compactRows(r)
		return h, rw, t, nil
	case ViewLifecycle:
		h, rw, t := lifecycleRows(r)
		return h, rw, t, nil
	case ViewDrift:
		h, rw, t := driftRows(r)
		return h, rw, t, nil
	case ViewFleet:
		h, rw, t := fleetRows(r)
		return h, rw, t, nil
	default:
		return nil, nil, nil, fmt.Errorf("unknown view %q", view)
	}
}
