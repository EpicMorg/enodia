// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"io"
	"strings"

	"github.com/EpicMorg/enodia/internal/evaluate"
)

// Prometheus writes the report as a Prometheus textfile-collector
// exposition (https://prometheus.io/docs/instrumenting/exposition_formats/).
// Each D6 axis is exposed as an "info"-style gauge — value 1, the state as
// a label — so PromQL can select or count by state; OverallSeverity is also
// exposed as a plain number for threshold alerting, and eol/support dates
// as Unix timestamps for "days until" alerts.
//
// A metric is only written for targets where it applies: there is no
// enodia_eol_timestamp_seconds series at all for a target with no known EOL
// date, rather than a misleading 0 (which would read as 1970).
func Prometheus(w io.Writer, r Report) error {
	ew := &errWriter{w: w}

	metricHeader(ew, "enodia_target_info", "Static metadata about one probed target.")
	for _, a := range r.Assessments {
		ew.printf("enodia_target_info{id=%s,product=%s} 1\n", label(a.ID), label(a.Product))
	}

	metricHeader(ew, "enodia_patch_status", "Patch axis (D6); 1 marks the target's current state.")
	for _, a := range r.Assessments {
		ew.printf("enodia_patch_status{id=%s,status=%s} 1\n", label(a.ID), label(string(a.Patch)))
	}

	metricHeader(ew, "enodia_lifecycle_status", "Lifecycle axis (D6); 1 marks the target's current state.")
	for _, a := range r.Assessments {
		ew.printf("enodia_lifecycle_status{id=%s,status=%s} 1\n", label(a.ID), label(string(a.Lifecycle)))
	}

	metricHeader(ew, "enodia_branch_status", "Newer-branch axis (D6); 1 marks the target's current state.")
	for _, a := range r.Assessments {
		ew.printf("enodia_branch_status{id=%s,status=%s} 1\n", label(a.ID), label(string(a.Branch)))
	}

	metricHeader(ew, "enodia_severity", "Worst-case severity: 0 none, 1 info, 2 warn, 3 fail.")
	for _, a := range r.Assessments {
		ew.printf("enodia_severity{id=%s} %d\n", label(a.ID), severityNumber(a.OverallSeverity()))
	}

	metricHeader(ew, "enodia_eol_timestamp_seconds", "Unix time the matched cycle reaches end of life, if known.")
	for _, a := range r.Assessments {
		if a.EOLDate != nil {
			ew.printf("enodia_eol_timestamp_seconds{id=%s} %d\n", label(a.ID), a.EOLDate.Unix())
		}
	}

	metricHeader(ew, "enodia_support_end_timestamp_seconds", "Unix time active support ends for the matched cycle, if known.")
	for _, a := range r.Assessments {
		if a.SupportEnds != nil {
			ew.printf("enodia_support_end_timestamp_seconds{id=%s} %d\n", label(a.ID), a.SupportEnds.Unix())
		}
	}

	return ew.err
}

func metricHeader(ew *errWriter, name, help string) {
	ew.printf("# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
}

func severityNumber(s evaluate.Severity) int {
	switch s {
	case evaluate.SeverityFail:
		return 3
	case evaluate.SeverityWarn:
		return 2
	case evaluate.SeverityInfo:
		return 1
	default:
		return 0
	}
}

// label quotes and escapes a Prometheus label value per the exposition
// format: backslash, double quote and newline are the only characters that
// need it.
func label(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
