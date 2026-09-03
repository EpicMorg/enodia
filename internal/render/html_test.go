// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"bytes"
	"strings"
	"testing"
)

func TestHTMLIsSelfContained(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleReport()); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	for _, forbidden := range []string{"http://", "https://", "<script"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("output contains %q; the report must be self-contained (D14)", forbidden)
		}
	}
	if !strings.Contains(out, "<style>") {
		t.Fatal("expected inline CSS")
	}
}

func TestHTMLIsWellFormedEnough(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleReport()); err != nil {
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
	if err := HTML(&buf, sampleReport()); err != nil {
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
	if err := HTML(&buf, r); err != nil {
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
	if err := HTML(&buf, Report{}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	if strings.Count(out, "no data") != 4 {
		t.Fatalf("expected all four sections to report \"no data\", got:\n%s", out)
	}
}
