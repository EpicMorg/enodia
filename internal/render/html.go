// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"fmt"
	"html"
	"io"
	"strings"
	"time"
)

// The two HTMLOptions.Assets values.
const (
	// AssetsInline is the default: today's fully offline single file,
	// inline CSS, no external resources of any kind — it works wherever
	// it ends up served, including a closed network with no path to a
	// CDN (D19).
	AssetsInline = "inline"
	// AssetsCDN loads Bootstrap and a Bootswatch theme from jsdelivr
	// instead. The browser opening the page needs internet access for it
	// to render correctly — the page says so visibly (D19), not just in
	// a CLI warning at export time.
	AssetsCDN = "cdn"
)

// bootswatchVersion pins the exact Bootstrap/Bootswatch release CDN mode
// loads. An unpinned "latest" could change (or break) every previously
// generated report's styling without enodia itself changing at all — the
// same reasoning as pinning any other CDN dependency.
const bootswatchVersion = "5.3.3"

// bootswatchThemes is every theme bootswatch.com offers as of
// bootswatchVersion, in the order they're listed there. The generated
// page's own theme picker, and the client-side check that decides whether
// a viewer's stored localStorage value is still valid, both read this
// exact list — if Bootswatch renames or drops one, this needs updating
// too, or the two would drift apart.
var bootswatchThemes = []string{
	"default", "brite", "cerulean", "cosmo", "cyborg", "darkly", "flatly",
	"journal", "litera", "lumen", "lux", "materia", "minty", "morph",
	"pulse", "quartz", "sandstone", "simplex", "sketchy", "slate", "solar",
	"spacelab", "superhero", "united", "vapor", "yeti", "zephyr",
}

func isBootswatchTheme(name string) bool {
	for _, t := range bootswatchThemes {
		if t == name {
			return true
		}
	}
	return false
}

// HTMLOptions controls how HTML renders. The zero value (Assets "" and
// View "") is exactly the tool's original behaviour: fully offline, all
// four views stacked in one file.
type HTMLOptions struct {
	// Assets is AssetsInline (default when empty) or AssetsCDN.
	Assets string
	// View restricts the report to one view instead of all four stacked
	// sections. Empty means all four, as HTML always used to render.
	View View
	// Theme is a Bootswatch theme name, meaningful only when Assets is
	// AssetsCDN. Empty resolves to "default" (Bootswatch's own baseline
	// theme) — and that resolved value is what the page's initial
	// stylesheet AND its localStorage-reset target both use, so an
	// operator's own configured default (settings.yaml's html.theme) is
	// what a corrupted or unrecognised stored choice resets to, never an
	// unrelated hardcoded name (D19).
	Theme string
}

// htmlViewSection pairs one View with the heading its section renders
// under; htmlSections is the fixed stacked order when no single View is
// requested.
type htmlViewSection struct {
	view  View
	title string
}

var htmlSections = []htmlViewSection{
	{ViewCompact, "Compact"},
	{ViewLifecycle, "Lifecycle"},
	{ViewDrift, "Drift"},
	{ViewFleet, "Fleet"},
}

func findHTMLSection(v View) (htmlViewSection, error) {
	for _, s := range htmlSections {
		if s.view == v {
			return s, nil
		}
	}
	return htmlViewSection{}, fmt.Errorf("unknown view %q", v)
}

// HTML writes one report file per opts. See HTMLOptions for what each field
// does; the zero value reproduces the tool's original single-file, fully
// offline, all-views report exactly.
func HTML(w io.Writer, r Report, opts HTMLOptions) error {
	sections := htmlSections
	if opts.View != "" {
		s, err := findHTMLSection(opts.View)
		if err != nil {
			return err
		}
		sections = []htmlViewSection{s}
	}

	switch opts.Assets {
	case "", AssetsInline:
		return htmlInline(w, r, sections)
	case AssetsCDN:
		return htmlCDN(w, r, sections, opts.Theme)
	default:
		return fmt.Errorf("html assets %q is not %q or %q", opts.Assets, AssetsInline, AssetsCDN)
	}
}

// htmlInline is the original renderer: inline CSS, no external resources of
// any kind (D19).
func htmlInline(w io.Writer, r Report, sections []htmlViewSection) error {
	ew := &errWriter{w: w}

	ew.printf("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n")
	ew.printf("<title>enodia report</title>\n<style>%s</style>\n</head><body>\n", htmlCSS)
	ew.printf("<h1>enodia report</h1>\n")
	ew.printf("<p class=\"meta\">generated %s &middot; as of %s</p>\n",
		html.EscapeString(r.GeneratedAt.Format(time.RFC3339)),
		html.EscapeString(r.AsOf.Format(time.RFC3339)))

	for _, s := range sections {
		headers, rows, _, _ := viewRows(s.view, r) // s.view is always one of the known constants
		writeHTMLSection(ew, s.title, headers, rows, nil, "")
	}

	ew.printf("</body></html>\n")
	return ew.err
}

// htmlCDN loads Bootstrap + a Bootswatch theme from jsdelivr instead of
// inline CSS, adds a theme picker backed by localStorage, and a visible
// warning that the page needs internet access to render correctly.
func htmlCDN(w io.Writer, r Report, sections []htmlViewSection, theme string) error {
	if theme == "" {
		theme = "default"
	}
	if !isBootswatchTheme(theme) {
		return fmt.Errorf("html theme %q is not a known Bootswatch theme", theme)
	}

	ew := &errWriter{w: w}

	ew.printf("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n")
	ew.printf("<title>enodia report</title>\n")
	ew.printf("<link id=\"enodia-theme-css\" rel=\"stylesheet\" href=\"%s\">\n", bootswatchHref(theme))
	ew.printf("<style>%s</style>\n</head><body>\n", htmlCDNExtraCSS)
	ew.printf("<div class=\"container py-4\">\n")

	ew.printf("<div class=\"d-flex justify-content-between align-items-start flex-wrap gap-3 mb-3\">\n")
	ew.printf("<div>\n<h1 class=\"mb-1\">enodia report</h1>\n")
	ew.printf("<p class=\"text-body-secondary mb-0\">generated %s &middot; as of %s</p>\n</div>\n",
		html.EscapeString(r.GeneratedAt.Format(time.RFC3339)),
		html.EscapeString(r.AsOf.Format(time.RFC3339)))
	ew.printf("<div>\n<label for=\"enodia-theme-picker\" class=\"form-label mb-1 small\">Theme</label>\n")
	ew.printf("<select id=\"enodia-theme-picker\" class=\"form-select form-select-sm\">\n")
	for _, t := range bootswatchThemes {
		selectedAttr := ""
		if t == theme {
			selectedAttr = " selected"
		}
		ew.printf("<option value=\"%s\"%s>%s</option>\n", t, selectedAttr, html.EscapeString(themeLabel(t)))
	}
	ew.printf("</select>\n</div>\n</div>\n")

	ew.printf("<div class=\"alert alert-warning\" role=\"alert\">This report loads Bootstrap and its theme " +
		"from a CDN (jsdelivr) — it needs internet access in the browser to render correctly. Generate " +
		"with the default inline assets (<code>html.assets: inline</code>) for a fully offline report.</div>\n")

	for _, s := range sections {
		headers, rows, tones, _ := viewRows(s.view, r)
		writeHTMLSection(ew, s.title, headers, rows, tones, "table table-striped table-hover table-sm align-middle")
	}

	ew.printf("</div>\n")
	ew.printf("<script>%s</script>\n", themePickerScript(theme))
	ew.printf("</body></html>\n")
	return ew.err
}

func bootswatchHref(theme string) string {
	return fmt.Sprintf(
		"https://cdn.jsdelivr.net/npm/bootswatch@%s/dist/%s/bootstrap.min.css",
		bootswatchVersion, theme,
	)
}

// themeLabel titlecases a Bootswatch theme's slug for the picker's visible
// option text ("lumen" -> "Lumen"). Every name in bootswatchThemes is
// plain ASCII lowercase, so a byte slice is safe here.
func themeLabel(theme string) string {
	if theme == "" {
		return theme
	}
	return strings.ToUpper(theme[:1]) + theme[1:]
}

// themePickerScript is the only inline JS this report ever carries, and
// only in CDN mode: it reads a per-viewer theme choice back from
// localStorage, applies it, and writes back any change the picker makes.
// bakedDefault is the theme this exact report was generated with — an
// unrecognised or corrupted stored value resets to that, not to a
// hardcoded theme unrelated to what the operator configured (D19).
func themePickerScript(bakedDefault string) string {
	knownJSON := "["
	for i, t := range bootswatchThemes {
		if i > 0 {
			knownJSON += ","
		}
		knownJSON += fmt.Sprintf("%q", t)
	}
	knownJSON += "]"

	return fmt.Sprintf(`(function(){
var KNOWN = %s;
var DEFAULT = %q;
var KEY = "enodia-theme";
var css = document.getElementById("enodia-theme-css");
var picker = document.getElementById("enodia-theme-picker");
function href(theme) { return "https://cdn.jsdelivr.net/npm/bootswatch@%s/dist/" + theme + "/bootstrap.min.css"; }
function isKnown(theme) { return KNOWN.indexOf(theme) !== -1; }
function apply(theme) {
  css.setAttribute("href", href(theme));
  picker.value = theme;
}
try {
  var stored = window.localStorage.getItem(KEY);
  if (stored && isKnown(stored)) {
    if (stored !== DEFAULT) { apply(stored); }
  } else if (stored) {
    window.localStorage.setItem(KEY, DEFAULT);
  }
} catch (e) { /* localStorage unavailable (private mode, etc.) — the baked default already applies */ }
picker.addEventListener("change", function() {
  var theme = picker.value;
  if (!isKnown(theme)) { theme = DEFAULT; }
  apply(theme);
  try { window.localStorage.setItem(KEY, theme); } catch (e) {}
});
})();`, knownJSON, bakedDefault, bootswatchVersion)
}

// toneClass maps a RowTone to the Bootstrap contextual table class that
// carries the same meaning in every Bootswatch theme: table-success/-info/
// -warning/-danger are part of Bootstrap's own standardised variable set,
// not something each theme redefines independently, so a chosen theme's
// red/yellow/green always come out looking like that theme's palette, not
// enodia's own guess at the colors. Only meaningful in CDN mode — inline
// mode never has Bootstrap loaded to interpret these classes at all.
func toneClass(t RowTone) string {
	switch t {
	case ToneGood:
		return "table-success"
	case ToneInfo:
		return "table-info"
	case ToneWarn:
		return "table-warning"
	case ToneBad:
		return "table-danger"
	default:
		return ""
	}
}

// writeHTMLSection writes one view's table. tones may be nil (inline mode,
// which has no Bootstrap loaded to give table-* classes any meaning) or
// aligned one-to-one with rows.
func writeHTMLSection(ew *errWriter, title string, headers []string, rows [][]string, tones []RowTone, tableClass string) {
	ew.printf("<section>\n<h2>%s</h2>\n", html.EscapeString(title))
	if len(rows) == 0 {
		ew.printf("<p class=\"empty\">no data</p>\n</section>\n")
		return
	}

	if tableClass != "" {
		ew.printf("<table class=\"%s\">\n<thead><tr>", tableClass)
	} else {
		ew.printf("<table>\n<thead><tr>")
	}
	for _, h := range headers {
		ew.printf("<th>%s</th>", html.EscapeString(h))
	}
	ew.printf("</tr></thead>\n<tbody>\n")
	for i, row := range rows {
		rowClass := ""
		if i < len(tones) {
			rowClass = toneClass(tones[i])
		}
		if rowClass != "" {
			ew.printf("<tr class=\"%s\">", rowClass)
		} else {
			ew.printf("<tr>")
		}
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

// htmlCDNExtraCSS is small styling Bootstrap/Bootswatch don't cover on
// their own — the section spacing and "no data" placeholder look enodia's
// own inline CSS already gets right.
const htmlCDNExtraCSS = `
section { margin-bottom: 2.5rem; }
.empty { font-style: italic; }
`
