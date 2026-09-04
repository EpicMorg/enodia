// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/EpicMorg/enodia/internal/evaluate"
)

// "Self-contained" means no auto-fetched external resource: no
// stylesheet/script src pointing off-page, and no inline <script> at all
// (inline mode has none — CDN mode's script is what races/applies a
// theme). A plain <a href> in the footer is not a resource load — the
// page still renders fully offline, the link just sits there inert until
// a viewer with internet clicks it — so it does not belong on this list.
func TestHTMLIsSelfContained(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleReport(), HTMLOptions{}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	for _, forbidden := range []string{`<link rel="stylesheet" href="http`, "<script src=", "<script>"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("output contains %q; the default inline report must be self-contained (D19)", forbidden)
		}
	}
	if !strings.Contains(out, "<style>") {
		t.Fatal("expected inline CSS")
	}
	if !strings.Contains(out, "github.com/EpicMorg/enodia") {
		t.Fatal("expected the footer's link back to the project")
	}
}

func TestHTMLIsWellFormedEnough(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleReport(), HTMLOptions{}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "<!doctype html>") {
		t.Fatal("missing doctype")
	}
	if !strings.HasSuffix(strings.TrimRight(out, "\n"), "</html>") {
		t.Fatal("missing closing </html>")
	}
	for _, tag := range []string{"<html", "</html>", "<head>", "</head>", "<body>", "</body>"} {
		if !strings.Contains(out, tag) {
			t.Errorf("missing %s", tag)
		}
	}
}

func TestHTMLContainsAllFourSections(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleReport(), HTMLOptions{}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	for _, title := range []string{"Compact", "Lifecycle", "Drift", "Fleet"} {
		if !strings.Contains(out, "<h2>"+title+"</h2>") {
			t.Errorf("missing section %q", title)
		}
	}
}

func TestHTMLEscapesCellContent(t *testing.T) {
	r := sampleReport()
	r.Assessments[0].ID = `<script>alert(1)</script>`
	r.Observations = nil // keep the drift/fleet views simple for this check

	var buf bytes.Buffer
	if err := HTML(&buf, r, HTMLOptions{}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Fatal("unescaped content made it into the HTML output")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatalf("expected the ID to be HTML-escaped, got:\n%s", out)
	}
}

func TestHTMLEmptyReportRendersNoDataSections(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, Report{}, HTMLOptions{}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	if strings.Count(out, "no data") != 4 {
		t.Fatalf("expected all four sections to report \"no data\", got:\n%s", out)
	}
}

func TestHTMLViewOptionRestrictsToOneSection(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleReport(), HTMLOptions{View: ViewFleet}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "<h2>Fleet</h2>") {
		t.Fatal("expected the Fleet section")
	}
	for _, title := range []string{"Compact", "Lifecycle", "Drift"} {
		if strings.Contains(out, "<h2>"+title+"</h2>") {
			t.Errorf("View: ViewFleet still rendered the %q section", title)
		}
	}
}

func TestHTMLUnknownViewOptionErrors(t *testing.T) {
	var buf bytes.Buffer
	err := HTML(&buf, sampleReport(), HTMLOptions{View: View("bogus")})
	if err == nil {
		t.Fatal("expected an error for an unknown View option")
	}
}

func TestHTMLUnknownAssetsErrors(t *testing.T) {
	var buf bytes.Buffer
	err := HTML(&buf, sampleReport(), HTMLOptions{Assets: "bogus"})
	if err == nil {
		t.Fatal("expected an error for an unknown Assets option")
	}
}

func TestHTMLCDNLoadsBootswatchTheme(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleReport(), HTMLOptions{Assets: AssetsCDN, Theme: "lumen"}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "bootswatch@"+bootswatchVersion+"/dist/lumen/bootstrap.min.css") {
		t.Fatalf("expected the lumen Bootswatch stylesheet, got:\n%s", out)
	}
	if !strings.Contains(out, `<option value="lumen" selected>Lumen</option>`) {
		t.Fatalf("expected lumen preselected in the theme picker, got:\n%s", out)
	}
	if !strings.Contains(out, "needs internet access") {
		t.Fatal("expected a visible warning that CDN mode needs internet access")
	}
	if !strings.Contains(out, "<script>") {
		t.Fatal("expected the theme-picker script in CDN mode")
	}
}

// ThemeDefault is plain Bootstrap from the bootstrap package, not a
// "default" folder in bootswatch's own package — that folder doesn't
// exist (confirmed live against the real CDN, see html.go's comment on
// ThemeDefault). An earlier version of this test asserted the wrong,
// nonexistent path and would have passed against a 404.
func TestHTMLCDNEmptyThemeDefaultsToPlainBootstrap(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleReport(), HTMLOptions{Assets: AssetsCDN}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "bootstrap@"+bootstrapVersion+"/dist/css/bootstrap.min.css") {
		t.Fatalf("expected plain Bootstrap from the bootstrap package, got:\n%s", out)
	}
	if strings.Contains(out, "bootswatch@"+bootswatchVersion+"/dist/default/") {
		t.Fatalf("bootswatch has no \"default\" folder; this URL 404s, got:\n%s", out)
	}
}

func TestHTMLCDNThemeNoneLoadsNoStylesheetAndNoWarning(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleReport(), HTMLOptions{Assets: AssetsCDN, Theme: ThemeNone}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	// The <link> tag itself must carry no href — nothing is fetched on a
	// normal page load. The inline script mentioning CDN domains at all
	// is fine and expected: it still needs to know how to build a URL for
	// whatever theme a viewer picks next from the dropdown.
	if !strings.Contains(out, `<link id="enodia-theme-css" rel="stylesheet">`) {
		t.Fatalf("expected the theme <link> with no href in ThemeNone, got:\n%s", out)
	}
	if strings.Contains(out, `<link id="enodia-theme-css" rel="stylesheet" href=`) {
		t.Fatalf("ThemeNone must not set an href that would trigger a CDN fetch, got:\n%s", out)
	}
	if strings.Contains(out, "needs internet access") {
		t.Fatal("ThemeNone loads nothing, so the internet-access warning would be false — must not appear")
	}
	if !strings.Contains(out, `<option value="none" selected>None</option>`) {
		t.Fatalf("expected \"none\" preselected in the theme picker, got:\n%s", out)
	}
}

func TestHTMLCDNThemePickerListsNoneAndDefaultFirst(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleReport(), HTMLOptions{Assets: AssetsCDN}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	noneIdx := strings.Index(out, `value="none"`)
	defaultIdx := strings.Index(out, `value="default"`)
	lumenIdx := strings.Index(out, `value="lumen"`)
	if noneIdx == -1 || defaultIdx == -1 || lumenIdx == -1 {
		t.Fatalf("expected none, default and lumen options, got:\n%s", out)
	}
	if noneIdx >= defaultIdx || defaultIdx >= lumenIdx {
		t.Fatalf("expected None then Default then the real themes, got:\n%s", out)
	}
}

func TestHTMLCDNWarningAlertIsDismissible(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleReport(), HTMLOptions{Assets: AssetsCDN}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `class="alert alert-dismissible alert-warning"`) {
		t.Fatalf("expected a dismissible warning alert, got:\n%s", out)
	}
	if !strings.Contains(out, `class="btn-close" data-bs-dismiss="alert"`) {
		t.Fatalf("expected a close button on the warning alert, got:\n%s", out)
	}
	if !strings.Contains(out, `.btn-close[data-bs-dismiss="alert"]`) {
		t.Fatal("expected the script to wire up the close button (no bootstrap.bundle.js is loaded to do it for us)")
	}
}

func TestHTMLCDNThemeNoneOmitsWarningAlertEntirely(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleReport(), HTMLOptions{Assets: AssetsCDN, Theme: ThemeNone}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if strings.Contains(buf.String(), "alert-dismissible") {
		t.Fatal("ThemeNone loads nothing, so there is nothing to warn about")
	}
}

func TestHTMLFootersCreditTheProject(t *testing.T) {
	for _, opts := range []HTMLOptions{{}, {Assets: AssetsCDN}} {
		var buf bytes.Buffer
		if err := HTML(&buf, sampleReport(), opts); err != nil {
			t.Fatalf("HTML(%+v): %v", opts, err)
		}
		out := buf.String()
		if !strings.Contains(out, "<footer") {
			t.Fatalf("opts=%+v: expected a <footer>, got:\n%s", opts, out)
		}
		if !strings.Contains(out, `href="https://github.com/EpicMorg/enodia"`) {
			t.Fatalf("opts=%+v: expected a link back to the project, got:\n%s", opts, out)
		}
		if !strings.Contains(out, "AGPL-3.0-or-later") {
			t.Fatalf("opts=%+v: expected the license named in the footer, got:\n%s", opts, out)
		}
	}
}

func TestHTMLCDNFooterCreditsBootstrapAndBootswatch(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleReport(), HTMLOptions{Assets: AssetsCDN, Theme: "lumen"}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	for _, want := range []string{`href="https://getbootstrap.com/"`, `href="https://bootswatch.com/"`, "MIT License"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in the footer, got:\n%s", want, out)
		}
	}
}

func TestHTMLCDNThemeNoneFooterSkipsBootstrapCredit(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleReport(), HTMLOptions{Assets: AssetsCDN, Theme: ThemeNone}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if strings.Contains(buf.String(), "getbootstrap.com") {
		t.Fatal("ThemeNone loads neither Bootstrap nor Bootswatch, so crediting them would be false")
	}
}

func TestHTMLInlineFooterHasNoBootstrapCredit(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleReport(), HTMLOptions{}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if strings.Contains(buf.String(), "getbootstrap.com") {
		t.Fatal("inline mode never loads Bootstrap; nothing to credit")
	}
}

func TestHTMLCDNUnknownThemeErrors(t *testing.T) {
	var buf bytes.Buffer
	err := HTML(&buf, sampleReport(), HTMLOptions{Assets: AssetsCDN, Theme: "not-a-real-theme"})
	if err == nil {
		t.Fatal("expected an error for an unknown Bootswatch theme")
	}
}

func TestHTMLCDNUnknownCDNErrors(t *testing.T) {
	var buf bytes.Buffer
	err := HTML(&buf, sampleReport(), HTMLOptions{Assets: AssetsCDN, CDN: "not-a-real-cdn"})
	if err == nil {
		t.Fatal("expected an error for an unknown CDN option")
	}
}

func TestHTMLCDNExplicitCDNPinsOneSourceNoRace(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleReport(), HTMLOptions{Assets: AssetsCDN, Theme: "lumen", CDN: "cdnjs"}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `href="https://cdnjs.cloudflare.com/ajax/libs/bootswatch/`+bootswatchVersion+`/lumen/bootstrap.min.css"`) {
		t.Fatalf("expected the initial <link> to point straight at cdnjs, got:\n%s", out)
	}
	if !strings.Contains(out, "var RACE = false;") {
		t.Fatalf("expected racing disabled when a CDN is pinned explicitly, got:\n%s", out)
	}
}

func TestHTMLCDNAutoRacesByDefault(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleReport(), HTMLOptions{Assets: AssetsCDN, Theme: "lumen"}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `href="https://cdn.jsdelivr.net/npm/bootswatch@`+bootswatchVersion+`/dist/lumen/bootstrap.min.css"`) {
		t.Fatalf("expected the initial (pre-race) <link> to point at jsdelivr, got:\n%s", out)
	}
	if !strings.Contains(out, "var RACE = true;") {
		t.Fatalf("expected racing enabled by default, got:\n%s", out)
	}
	if !strings.Contains(out, "cdnjs.cloudflare.com/ajax/libs/bootswatch/"+bootswatchVersion+"/") {
		t.Fatal("expected the script to also know the cdnjs mirror URL to race against")
	}
}

// The theme picker's fallback-on-invalid-localStorage target must be this
// report's own baked theme, not a hardcoded name unrelated to it (D19): an
// operator who configured "lumen" as their default gets reports that reset
// back to lumen, never silently to Bootswatch's own "Default".
// table-success/-warning/-danger are Bootstrap's own standardised
// contextual classes: every Bootswatch theme redefines the same variables
// for them, so a chosen theme's palette drives the actual colors, not a
// hardcoded hex enodia would otherwise have to pick and maintain per theme.
func TestHTMLCDNRowsCarryBootstrapContextualClasses(t *testing.T) {
	r := sampleReport()
	r.Assessments[0].PatchSeverity = evaluate.SeverityFail // jira-a: force a bad row to exercise table-danger

	var buf bytes.Buffer
	if err := HTML(&buf, r, HTMLOptions{Assets: AssetsCDN}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	for _, class := range []string{"table-danger", "table-warning", "table-success"} {
		if !strings.Contains(out, `class="`+class+`"`) {
			t.Errorf("expected a row with class %q, got:\n%s", class, out)
		}
	}
}

func TestHTMLInlineRowsCarryNoBootstrapClasses(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleReport(), HTMLOptions{}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	for _, class := range []string{"table-danger", "table-warning", "table-success", "table-info"} {
		if strings.Contains(out, class) {
			t.Errorf("inline mode has no Bootstrap loaded; found stray class %q", class)
		}
	}
}

func TestHTMLCDNScriptResetsToBakedTheme(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleReport(), HTMLOptions{Assets: AssetsCDN, Theme: "darkly"}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `var BAKED = "darkly"`) {
		t.Fatalf("expected the script's fallback constant to be the baked theme (darkly), got:\n%s", out)
	}
}
