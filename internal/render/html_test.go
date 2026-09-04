// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/EpicMorg/enodia/internal/evaluate"
)

func TestHTMLIsSelfContained(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleReport(), HTMLOptions{}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	for _, forbidden := range []string{"http://", "https://", "<script"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("output contains %q; the default inline report must be self-contained (D19)", forbidden)
		}
	}
	if !strings.Contains(out, "<style>") {
		t.Fatal("expected inline CSS")
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

func TestHTMLCDNEmptyThemeDefaultsToDefault(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleReport(), HTMLOptions{Assets: AssetsCDN}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "dist/default/bootstrap.min.css") {
		t.Fatalf("expected the default Bootswatch theme, got:\n%s", out)
	}
}

func TestHTMLCDNUnknownThemeErrors(t *testing.T) {
	var buf bytes.Buffer
	err := HTML(&buf, sampleReport(), HTMLOptions{Assets: AssetsCDN, Theme: "not-a-real-theme"})
	if err == nil {
		t.Fatal("expected an error for an unknown Bootswatch theme")
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
	if !strings.Contains(out, `var DEFAULT = "darkly"`) {
		t.Fatalf("expected the script's fallback constant to be the baked theme (darkly), got:\n%s", out)
	}
}
