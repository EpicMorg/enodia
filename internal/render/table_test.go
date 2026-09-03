// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"bytes"
	"strings"
	"testing"
)

func TestTableCompactContainsHeaderAndRows(t *testing.T) {
	var buf bytes.Buffer
	if err := Table(&buf, ViewCompact, sampleReport()); err != nil {
		t.Fatalf("Table: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "ID") || !strings.Contains(out, "SEVERITY") {
		t.Fatalf("missing header columns:\n%s", out)
	}
	if !strings.Contains(out, "jira-a") || !strings.Contains(out, "down") {
		t.Fatalf("missing expected rows:\n%s", out)
	}
}

func TestTableEmptyViewIsCompact(t *testing.T) {
	var buf bytes.Buffer
	if err := Table(&buf, "", sampleReport()); err != nil {
		t.Fatalf("Table: %v", err)
	}
	if !strings.Contains(buf.String(), "SEVERITY") {
		t.Fatalf("empty view did not render compact:\n%s", buf.String())
	}
}

func TestTableEveryView(t *testing.T) {
	for _, v := range []View{ViewCompact, ViewLifecycle, ViewDrift, ViewFleet} {
		var buf bytes.Buffer
		if err := Table(&buf, v, sampleReport()); err != nil {
			t.Fatalf("Table(%s): %v", v, err)
		}
		if buf.Len() == 0 {
			t.Fatalf("Table(%s) produced no output", v)
		}
	}
}

func TestTableUnknownViewErrors(t *testing.T) {
	var buf bytes.Buffer
	if err := Table(&buf, "bogus", sampleReport()); err == nil {
		t.Fatal("expected an error for an unknown view")
	}
}

func TestTableColumnsArePadded(t *testing.T) {
	var buf bytes.Buffer
	if err := Table(&buf, ViewCompact, sampleReport()); err != nil {
		t.Fatalf("Table: %v", err)
	}
	// tabwriter pads narrower cells with spaces to align columns; a raw
	// tab-joined dump would have none of these runs.
	if !strings.Contains(buf.String(), "  ") {
		t.Fatalf("output does not look column-aligned:\n%s", buf.String())
	}
}
