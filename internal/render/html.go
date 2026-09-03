// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"html"
	"io"
	"time"
)

// htmlViews is the fixed order sections appear in; there is no client-side
// interactivity (no JS, no CSS-only tab trick) — just four stacked
// sections. This is a static report meant to be regenerated and re-served,
// not an application (D14).
var htmlViews = []struct {
	view  View
	title string
}{
	{ViewCompact, "Compact"},
	{ViewLifecycle, "Lifecycle"},
	{ViewDrift, "Drift"},
	{ViewFleet, "Fleet"},
}

// HTML writes one self-contained report file: inline CSS, no external
// resources of any kind, so it works wherever it ends up served — including
// a closed network with no path to a CDN (D14).
func HTML(w io.Writer, r Report) error {
	ew := &errWriter{w: w}

	ew.printf("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n")
	ew.printf("<title>enodia report</title>\n<style>%s</style>\n</head><body>\n", htmlCSS)
	ew.printf("<h1>enodia report</h1>\n")
	ew.printf("<p class=\"meta\">generated %s &middot; as of %s</p>\n",
		html.EscapeString(r.GeneratedAt.Format(time.RFC3339)),
		html.EscapeString(r.AsOf.Format(time.RFC3339)))

	for _, v := range htmlViews {
		headers, rows, _ := viewRows(v.view, r) // v.view is always one of the known constants
		writeHTMLSection(ew, v.title, headers, rows)
	}

	ew.printf("</body></html>\n")
	return ew.err
}

func writeHTMLSection(ew *errWriter, title string, headers []string, rows [][]string) {
	ew.printf("<section>\n<h2>%s</h2>\n", html.EscapeString(title))
	if len(rows) == 0 {
		ew.printf("<p class=\"empty\">no data</p>\n</section>\n")
		return
	}

	ew.printf("<table>\n<thead><tr>")
	for _, h := range headers {
		ew.printf("<th>%s</th>", html.EscapeString(h))
	}
	ew.printf("</tr></thead>\n<tbody>\n")
	for _, row := range rows {
		ew.printf("<tr>")
		for _, cell := range row {
			ew.printf("<td>%s</td>", html.EscapeString(cell))
		}
		ew.printf("</tr>\n")
	}
	ew.printf("</tbody>\n</table>\n</section>\n")
}

const htmlCSS = `
:root { color-scheme: light dark; }
body { font-family: system-ui, sans-serif; margin: 2rem; line-height: 1.4; }
h1 { margin-bottom: 0.25rem; }
.meta { color: #666; margin-top: 0; }
section { margin-bottom: 2.5rem; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: 0.35rem 0.75rem; border-bottom: 1px solid #ccc; }
th { border-bottom: 2px solid #888; }
.empty { color: #888; font-style: italic; }
`
