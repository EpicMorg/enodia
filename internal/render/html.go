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
// same reasoning as pinning any other CDN dependency. Bootswatch tags a
// release for every Bootstrap release it tracks, so the two version
// numbers are always identical — bootstrapVersion below is not a
// separate thing to keep in sync by hand, it's the same number.
const bootswatchVersion = "5.3.8"
const bootstrapVersion = bootswatchVersion

// ThemeNone and ThemeDefault are the two HTMLOptions.Theme values that
// are not a real Bootswatch theme name:
//
//   - ThemeNone loads no stylesheet at all — every table still carries its
//     Bootstrap classes and RowTone-driven contextual classes in the
//     markup, but nothing gives them a visual meaning unless the page is
//     embedded somewhere that already loads its own Bootstrap. There is
//     also nothing to fetch from a CDN in this mode, so the "needs
//     internet access" warning is skipped — it would be false.
//   - ThemeDefault is plain, unthemed Bootstrap. bootswatch.com's own site
//     lists "Default" first as if it were one more theme, but there is no
//     such folder in the actual bootswatch npm/CDN package (confirmed
//     live: every version tried 404s) — it's their site linking straight
//     to plain Bootstrap. ThemeDefault reproduces that by loading the
//     bootstrap package directly instead of bootswatch's.
const (
	ThemeNone    = "none"
	ThemeDefault = "default"
)

// bootswatchThemes is every real theme bootswatch.com offers as of
// bootswatchVersion — confirmed against the actual npm package contents,
// not the marketing site's list, which is what caused ThemeDefault to be
// missing here in an earlier version of this file. The generated page's
// own theme picker, and the client-side check that decides whether a
// viewer's stored localStorage value is still valid, both read this exact
// list — if Bootswatch renames, adds, or drops one, this needs updating
// too, or the two would drift apart.
var bootswatchThemes = []string{
	"brite", "cerulean", "cosmo", "cyborg", "darkly", "flatly",
	"journal", "litera", "lumen", "lux", "materia", "minty", "morph",
	"pulse", "quartz", "sandstone", "simplex", "sketchy", "slate", "solar",
	"spacelab", "superhero", "united", "vapor", "yeti", "zephyr",
}

func isValidTheme(name string) bool {
	if name == ThemeNone || name == ThemeDefault {
		return true
	}
	for _, t := range bootswatchThemes {
		if t == name {
			return true
		}
	}
	return false
}

// The three HTMLOptions.CDN values. Both mirrors carry the same content —
// cdnjs's own bootswatch listing is a mirror of the same npm package
// jsdelivr serves — so switching between them is purely about which one
// actually answers from wherever the report is opened, not a difference
// in what gets loaded.
const (
	// CDNAuto (the default, empty also means this) races cdnJSDelivr and
	// cdnCDNJS with a HEAD request each and uses whichever answers first,
	// so one CDN being unreachable or slow from a given network doesn't
	// take the whole page's styling down with it.
	CDNAuto     = "auto"
	cdnJSDelivr = "jsdelivr"
	cdnCDNJS    = "cdnjs"
)

func isValidCDN(name string) bool {
	switch name {
	case "", CDNAuto, cdnJSDelivr, cdnCDNJS:
		return true
	default:
		return false
	}
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
	// Theme is ThemeNone, ThemeDefault, or a Bootswatch theme name,
	// meaningful only when Assets is AssetsCDN. Empty resolves to
	// ThemeDefault — and that resolved value is what the page's initial
	// stylesheet AND its localStorage-reset target both use, so an
	// operator's own configured default (settings.yaml's html.theme) is
	// what a corrupted or unrecognised stored choice resets to, never an
	// unrelated hardcoded name (D19).
	Theme string
	// CDN picks which CDN(s) serve Theme's stylesheet: "" / CDNAuto races
	// both and uses whichever answers first, "jsdelivr" or "cdnjs" pins
	// one explicitly (no race — a plain synchronous <link>, same as
	// before CDN racing existed). Meaningful only when Assets is
	// AssetsCDN and Theme is not ThemeNone.
	CDN string
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
		return htmlCDN(w, r, sections, opts.Theme, opts.CDN)
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

	writeHTMLFooterInline(ew, r)
	ew.printf("</body></html>\n")
	return ew.err
}

// htmlCDN loads Bootstrap (or a Bootswatch theme of it) from a CDN instead
// of inline CSS, adds a theme picker backed by localStorage, and — unless
// Theme is ThemeNone, which loads nothing — a visible warning that the
// page needs internet access to render correctly.
func htmlCDN(w io.Writer, r Report, sections []htmlViewSection, theme, cdn string) error {
	if theme == "" {
		theme = ThemeDefault
	}
	if !isValidTheme(theme) {
		return fmt.Errorf("html theme %q is not %q, %q, or a known Bootswatch theme", theme, ThemeNone, ThemeDefault)
	}
	if !isValidCDN(cdn) {
		return fmt.Errorf("html cdn %q is not %q, %q, or %q", cdn, CDNAuto, cdnJSDelivr, cdnCDNJS)
	}

	ew := &errWriter{w: w}

	ew.printf("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n")
	ew.printf("<title>enodia report</title>\n")
	if theme == ThemeNone {
		ew.printf("<link id=\"enodia-theme-css\" rel=\"stylesheet\">\n")
	} else {
		// The race (when cdn is "" or CDNAuto) only runs once the script
		// below executes; this synchronous href is what a viewer with
		// JavaScript disabled sees, and what everyone sees for the
		// instant before the script runs — jsdelivr, not a random pick,
		// so the page never flashes between two different stylesheets on
		// a normal load.
		initialSource := cdn
		if initialSource == "" || initialSource == CDNAuto {
			initialSource = cdnJSDelivr
		}
		ew.printf("<link id=\"enodia-theme-css\" rel=\"stylesheet\" href=\"%s\">\n", themeCSSURL(theme, initialSource))
	}
	ew.printf("<style>%s</style>\n</head><body>\n", htmlCDNExtraCSS)
	ew.printf("<div class=\"container py-4\">\n")

	ew.printf("<div class=\"d-flex justify-content-between align-items-start flex-wrap gap-3 mb-3\">\n")
	ew.printf("<div>\n<h1 class=\"mb-1\">enodia report</h1>\n")
	ew.printf("<p class=\"text-body-secondary mb-0\">generated %s &middot; as of %s</p>\n</div>\n",
		html.EscapeString(r.GeneratedAt.Format(time.RFC3339)),
		html.EscapeString(r.AsOf.Format(time.RFC3339)))
	ew.printf("<div>\n<label for=\"enodia-theme-picker\" class=\"form-label mb-1 small\">Theme</label>\n")
	ew.printf("<select id=\"enodia-theme-picker\" class=\"form-select form-select-sm\">\n")
	for _, t := range pickerThemes() {
		selectedAttr := ""
		if t == theme {
			selectedAttr = " selected"
		}
		ew.printf("<option value=\"%s\"%s>%s</option>\n", t, selectedAttr, html.EscapeString(themeLabel(t)))
	}
	ew.printf("</select>\n</div>\n</div>\n")

	if theme != ThemeNone {
		ew.printf("<div class=\"alert alert-dismissible alert-warning\" role=\"alert\">This report loads " +
			"Bootstrap and its theme from a CDN — it needs internet access in the browser to render " +
			"correctly. Generate with the default inline assets (<code>html.assets: inline</code>) for a " +
			"fully offline report, or <code>html.theme: none</code> for unstyled Bootstrap-class markup " +
			"with no CDN load at all." +
			"<button type=\"button\" class=\"btn-close\" data-bs-dismiss=\"alert\" aria-label=\"Close\"></button>" +
			"</div>\n")
	}

	for _, s := range sections {
		headers, rows, tones, _ := viewRows(s.view, r)
		writeHTMLSection(ew, s.title, headers, rows, tones, "table table-striped table-hover table-sm align-middle")
	}

	writeHTMLFooterCDN(ew, r, theme != ThemeNone)
	ew.printf("</div>\n")
	ew.printf("<script>%s</script>\n", cdnModeScript(theme, cdn))
	ew.printf("</body></html>\n")
	return ew.err
}

// writeHTMLFooterInline and writeHTMLFooterCDN both credit the project and
// link back to it — requested alongside the CDN theming work. The CDN
// variant also credits Bootstrap/Bootswatch by name with a link to each
// project and a note that both are MIT licensed, since CDN mode is the one
// case where this report actually depends on their code at view time (see
// README.md's "Third-party assets"); creditBootstrap is false for
// ThemeNone, which loads neither.
func writeHTMLFooterInline(ew *errWriter, r Report) {
	ew.printf("<footer>\n<p>enodia &middot; <a href=\"https://github.com/EpicMorg/enodia\">"+
		"github.com/EpicMorg/enodia</a> &middot; &copy; %d EpicMorg &middot; AGPL-3.0-or-later</p>\n</footer>\n",
		r.GeneratedAt.Year())
}

func writeHTMLFooterCDN(ew *errWriter, r Report, creditBootstrap bool) {
	ew.printf("<footer class=\"mt-5 pt-3 border-top text-body-secondary small\">\n")
	ew.printf("<p class=\"mb-1\">enodia &middot; <a href=\"https://github.com/EpicMorg/enodia\">"+
		"github.com/EpicMorg/enodia</a> &middot; &copy; %d EpicMorg &middot; AGPL-3.0-or-later</p>\n",
		r.GeneratedAt.Year())
	if creditBootstrap {
		ew.printf("<p class=\"mb-0\">Styled with <a href=\"https://getbootstrap.com/\">Bootstrap</a> and " +
			"<a href=\"https://bootswatch.com/\">Bootswatch</a> (MIT License).</p>\n")
	}
	ew.printf("</footer>\n")
}

// pickerThemes is the theme <select>'s full option list: None and Default
// first (they're not part of bootswatchThemes — see ThemeNone/ThemeDefault
// — but belong in the same picker), then every real Bootswatch theme.
func pickerThemes() []string {
	out := make([]string, 0, len(bootswatchThemes)+2)
	out = append(out, ThemeNone, ThemeDefault)
	return append(out, bootswatchThemes...)
}

// themeCSSURL is theme's stylesheet URL from the named source ("jsdelivr"
// or "cdnjs" — any other value, including "", falls back to jsdelivr).
// ThemeDefault is served from the bootstrap package itself: bootswatch's
// package carries no such folder (confirmed live against jsdelivr's own
// package file listing for this exact pinned version).
func themeCSSURL(theme, source string) string {
	if theme == ThemeDefault {
		if source == cdnCDNJS {
			return fmt.Sprintf("https://cdnjs.cloudflare.com/ajax/libs/bootstrap/%s/css/bootstrap.min.css", bootstrapVersion)
		}
		return fmt.Sprintf("https://cdn.jsdelivr.net/npm/bootstrap@%s/dist/css/bootstrap.min.css", bootstrapVersion)
	}
	if source == cdnCDNJS {
		return fmt.Sprintf("https://cdnjs.cloudflare.com/ajax/libs/bootswatch/%s/%s/bootstrap.min.css", bootswatchVersion, theme)
	}
	return fmt.Sprintf("https://cdn.jsdelivr.net/npm/bootswatch@%s/dist/%s/bootstrap.min.css", bootswatchVersion, theme)
}

// themeLabel titlecases a theme slug for the picker's visible option text
// ("lumen" -> "Lumen", "none" -> "None"). Every value it's ever called
// with is plain ASCII lowercase, so a byte slice is safe here.
func themeLabel(theme string) string {
	if theme == "" {
		return theme
	}
	return strings.ToUpper(theme[:1]) + theme[1:]
}

// cdnModeScript is the only inline JS this report ever carries, and only
// in CDN mode. It does two unrelated things in one IIFE rather than two
// separate <script> tags, purely to keep the page down to one script
// block: (1) theme handling — reads a per-viewer theme choice back from
// localStorage, applies it, races cdn's two mirrors when cdn is "" or
// CDNAuto, and writes back any change the picker makes; (2) dismissing the
// CDN warning alert on its close button click — Bootstrap's own Alert
// component needs bootstrap.bundle.min.js to do this, and pulling in a JS
// bundle just for one button's click handler isn't worth it when four
// lines of vanilla JS do the same thing.
//
// bakedTheme is the theme this exact report was generated with — an
// unrecognised or corrupted stored value resets to that, not to a
// hardcoded theme unrelated to what the operator configured (D19). Only
// the theme choice is remembered per viewer; which CDN(s) serve it is an
// operator setting (settings.yaml's html.cdn), not something a picker in
// the page exposes.
func cdnModeScript(bakedTheme, cdn string) string {
	known := make([]string, 0, len(bootswatchThemes)+2)
	known = append(known, ThemeNone, ThemeDefault)
	known = append(known, bootswatchThemes...)
	knownJSON := "["
	for i, t := range known {
		if i > 0 {
			knownJSON += ","
		}
		knownJSON += fmt.Sprintf("%q", t)
	}
	knownJSON += "]"

	racing := "false"
	if cdn == "" || cdn == CDNAuto {
		racing = "true"
	}

	return fmt.Sprintf(`(function(){
var KNOWN = %s;
var BAKED = %q;
var RACE = %s;
var KEY = "enodia-theme";
var css = document.getElementById("enodia-theme-css");
var picker = document.getElementById("enodia-theme-picker");
function isKnown(t) { return KNOWN.indexOf(t) !== -1; }
function urlFor(theme, source) {
  if (theme === "default") {
    return source === "cdnjs"
      ? "https://cdnjs.cloudflare.com/ajax/libs/bootstrap/%s/css/bootstrap.min.css"
      : "https://cdn.jsdelivr.net/npm/bootstrap@%s/dist/css/bootstrap.min.css";
  }
  return source === "cdnjs"
    ? "https://cdnjs.cloudflare.com/ajax/libs/bootswatch/%s/" + theme + "/bootstrap.min.css"
    : "https://cdn.jsdelivr.net/npm/bootswatch@%s/dist/" + theme + "/bootstrap.min.css";
}
function apply(theme) {
  if (theme === "none") { css.removeAttribute("href"); }
  else { css.setAttribute("href", urlFor(theme, "jsdelivr")); }
  picker.value = theme;
  if (theme !== "none" && RACE && window.Promise && Promise.any && window.fetch) {
    var urls = [urlFor(theme, "jsdelivr"), urlFor(theme, "cdnjs")];
    Promise.any(urls.map(function(u) {
      return fetch(u, {method: "HEAD", mode: "cors"}).then(function(r) {
        if (!r.ok) { throw new Error("bad status"); }
        return u;
      });
    })).then(function(winner) {
      if (css.getAttribute("href") !== winner) { css.setAttribute("href", winner); }
    }).catch(function() { /* both mirrors failed; the jsdelivr href already applied stays */ });
  }
}
try {
  var stored = window.localStorage.getItem(KEY);
  if (stored && isKnown(stored)) {
    if (stored !== BAKED) { apply(stored); } else if (RACE) { apply(BAKED); }
  } else {
    if (stored) { window.localStorage.setItem(KEY, BAKED); }
    if (RACE) { apply(BAKED); }
  }
} catch (e) { /* localStorage unavailable (private mode, etc.) — the baked default already applies */ }
picker.addEventListener("change", function() {
  var theme = picker.value;
  if (!isKnown(theme)) { theme = BAKED; }
  apply(theme);
  try { window.localStorage.setItem(KEY, theme); } catch (e) {}
});
var closeButtons = document.querySelectorAll('.alert .btn-close[data-bs-dismiss="alert"]');
for (var i = 0; i < closeButtons.length; i++) {
  closeButtons[i].addEventListener("click", function(e) {
    var alertEl = e.currentTarget.closest(".alert");
    if (alertEl) { alertEl.remove(); }
  });
}
})();`, knownJSON, bakedTheme, racing, bootstrapVersion, bootstrapVersion, bootswatchVersion, bootswatchVersion)
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
footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #ccc; color: #666; font-size: 0.85em; }
`

// htmlCDNExtraCSS is small styling Bootstrap/Bootswatch don't cover on
// their own — the section spacing and "no data" placeholder look enodia's
// own inline CSS already gets right.
const htmlCDNExtraCSS = `
section { margin-bottom: 2.5rem; }
.empty { font-style: italic; }
`
