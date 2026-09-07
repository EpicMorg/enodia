// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestJSONRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sampleReport()); err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var got Report
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if len(got.Assessments) != 4 || len(got.Observations) != 4 {
		t.Fatalf("got %d assessments, %d observations", len(got.Assessments), len(got.Observations))
	}
}

func TestJSONUsesCamelCaseFieldNames(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sampleReport()); err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	for _, field := range []string{"generatedAt", "asOf", "tool", "observations", "assessments"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("missing top-level field %q in %v", field, raw)
		}
	}

	assessments, ok := raw["assessments"].([]any)
	if !ok || len(assessments) == 0 {
		t.Fatalf("got %v", raw["assessments"])
	}
	first, ok := assessments[0].(map[string]any)
	if !ok {
		t.Fatalf("got %v", assessments[0])
	}
	for _, field := range []string{"id", "patch", "lifecycle", "branch", "patchSeverity"} {
		if _, ok := first[field]; !ok {
			t.Errorf("assessment missing camelCase field %q, got %v", field, first)
		}
	}
}
