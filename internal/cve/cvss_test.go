// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"path/filepath"
	"testing"
)

// Every input here is a real severity string from BDU's vulxml.zip, one
// per shape the full export actually contains.
func TestParseBDUSeverity(t *testing.T) {
	cases := []struct {
		name, in string
		want     cvss
		ok       bool
	}{
		{"3.0 preferred over 2.0, comma decimal",
			"Критический уровень опасности (базовая оценка CVSS 2.0 составляет 10)\nКритический уровень опасности (базовая оценка CVSS 3.0 составляет 9,8)",
			cvss{"3.0", 9.8, "CRITICAL"}, true},
		{"3.1 with a decimal point",
			"Средний уровень опасности (базовая оценка CVSS 2.0 составляет 5.6)\nСредний уровень опасности (базовая оценка CVSS 3.1 составляет 6.1)",
			cvss{"3.1", 6.1, "MEDIUM"}, true},
		{"2.0 only, integer score",
			"Высокий уровень опасности (базовая оценка CVSS 2.0 составляет 9,3)",
			cvss{"2.0", 9.3, "HIGH"}, true},
		{"4.0 without базовая, no-risk level",
			"Нет опасности уровень опасности (оценка CVSS 4.0 составляет 0)",
			cvss{"4.0", 0, "NONE"}, true},
		{"no-risk level without уровень опасности",
			"Нет опасности (базовая оценка CVSS 3.1 составляет 0)",
			cvss{"3.1", 0, "NONE"}, true},
		{"nothing parseable", "Данные уточняются", cvss{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := parseBDUSeverity(c.in)
			if got != c.want || ok != c.ok {
				t.Fatalf("got %+v, %v; want %+v, %v", got, ok, c.want, c.ok)
			}
		})
	}
}

// testdata/nvd_gitlab.json carries the real metrics of each record. Two
// of them have both a CNA (Secondary) and an NVD (Primary) 3.1 rating
// that disagree — NVD's own must be the one picked.
func TestLoadNVDPicksPrimaryCVSS(t *testing.T) {
	idx, err := LoadNVD(filepath.Join("testdata", "nvd_gitlab.json"))
	if err != nil {
		t.Fatalf("LoadNVD: %v", err)
	}
	want := map[string]CVSS{
		"CVE-2026-18252": {Version: "3.1", Score: 8.1, Severity: "HIGH"},     // Secondary says 7.3
		"CVE-2026-19478": {Version: "3.1", Score: 9.1, Severity: "CRITICAL"}, // Secondary says 9.4
		"CVE-2026-85706": {Version: "3.1", Score: 10, Severity: "CRITICAL"},  // Secondary only
	}
	for _, f := range idx.Lookup("gitlab", "19.2.2", "") {
		if w, ok := want[f.AdvisoryID]; ok && f.CVSS != w {
			t.Errorf("%s: got %+v, want %+v", f.AdvisoryID, f.CVSS, w)
		}
	}
}

// 3.x wins over a 4.0 rating on the same record, so every score in one
// list is on the same scale; the v2 shape keeps its severity top-level.
func TestNVDCVSSPreferenceAndV2Shape(t *testing.T) {
	got, ok := nvdCVSS(nvdMetrics{
		CVSSMetricV40: []nvdCVSSMetric{{Type: "Secondary", CVSSData: nvdCVSSData{BaseScore: 5.5, BaseSeverity: "MEDIUM"}}},
		CVSSMetricV31: []nvdCVSSMetric{{Type: "Secondary", CVSSData: nvdCVSSData{BaseScore: 7.3, BaseSeverity: "HIGH"}}},
	})
	if !ok || got != (cvss{"3.1", 7.3, "HIGH"}) {
		t.Fatalf("got %+v, %v; want 3.1 7.3 HIGH", got, ok)
	}
	got, ok = nvdCVSS(nvdMetrics{CVSSMetricV2: []nvdCVSSMetric{{CVSSData: nvdCVSSData{BaseScore: 7.5}, BaseSeverity: "HIGH"}}})
	if !ok || got != (cvss{"2.0", 7.5, "HIGH"}) {
		t.Fatalf("got %+v, %v; want 2.0 7.5 HIGH", got, ok)
	}
}
