// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/EpicMorg/enodia/internal/evaluate"
)

func TestPrometheusHasHelpAndTypeForEveryMetric(t *testing.T) {
	var buf bytes.Buffer
	if err := Prometheus(&buf, sampleReport()); err != nil {
		t.Fatalf("Prometheus: %v", err)
	}
	out := buf.String()
	for _, name := range []string{
		"enodia_target_info", "enodia_patch_status", "enodia_lifecycle_status",
		"enodia_branch_status", "enodia_severity",
	} {
		if !strings.Contains(out, "# HELP "+name+" ") {
			t.Errorf("missing HELP line for %s", name)
		}
		if !strings.Contains(out, "# TYPE "+name+" gauge") {
			t.Errorf("missing TYPE line for %s", name)
		}
	}
}

func TestPrometheusStatusIsInfoStyle(t *testing.T) {
	var buf bytes.Buffer
	if err := Prometheus(&buf, sampleReport()); err != nil {
		t.Fatalf("Prometheus: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `enodia_lifecycle_status{id="jira-a",status="security"} 1`) {
		t.Fatalf("missing expected lifecycle_status line:\n%s", out)
	}
}

func TestPrometheusOmitsEOLTimestampWhenUnknown(t *testing.T) {
	var buf bytes.Buffer
	if err := Prometheus(&buf, sampleReport()); err != nil {
		t.Fatalf("Prometheus: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, `enodia_eol_timestamp_seconds{id="confluence-a"}`) {
		t.Fatalf("confluence-a has no EOLDate; must not get a timestamp series:\n%s", out)
	}
	if !strings.Contains(out, `enodia_eol_timestamp_seconds{id="jira-a"}`) {
		t.Fatalf("jira-a has an EOLDate; expected a timestamp series:\n%s", out)
	}
}

func TestPrometheusEOLTimestampValue(t *testing.T) {
	var buf bytes.Buffer
	if err := Prometheus(&buf, sampleReport()); err != nil {
		t.Fatalf("Prometheus: %v", err)
	}
	// 2026-03-01T00:00:00Z
	if !strings.Contains(buf.String(), `enodia_eol_timestamp_seconds{id="jira-a"} 1772323200`) {
		t.Fatalf("unexpected eol timestamp value:\n%s", buf.String())
	}
}

func TestSeverityNumberOrdering(t *testing.T) {
	cases := []struct {
		s    evaluate.Severity
		want int
	}{
		{evaluate.SeverityNone, 0},
		{evaluate.SeverityInfo, 1},
		{evaluate.SeverityWarn, 2},
		{evaluate.SeverityFail, 3},
	}
	for _, c := range cases {
		if got := severityNumber(c.s); got != c.want {
			t.Errorf("severityNumber(%v) = %d, want %d", c.s, got, c.want)
		}
	}
}

func TestLabelEscaping(t *testing.T) {
	cases := []struct{ in, want string }{
		{`plain`, `"plain"`},
		{`with"quote`, `"with\"quote"`},
		{`with\backslash`, `"with\\backslash"`},
		{"with\nnewline", `"with\nnewline"`},
	}
	for _, c := range cases {
		if got := label(c.in); got != c.want {
			t.Errorf("label(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
