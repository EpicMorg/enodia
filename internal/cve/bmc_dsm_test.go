// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"path/filepath"
	"slices"
	"testing"
)

// testdata/nvd_bmc_dsm.json is four real NVD records, trimmed to the
// fields LoadNVD reads and to their iDRAC, iLO 4 and DSM matches:
// CVE-2019-3764 (iDRAC7 < 2.65.65.65, iDRAC8 < 2.70.70.70, iDRAC9 <
// 3.36.36.36), CVE-2025-22397 (two iDRAC9 7.x ranges), CVE-2023-28083
// (iLO 4 < 2.82) and CVE-2025-1021 (three DSM branches, bounded by
// build and Update).
func bmcDSMIDs(t *testing.T, product, raw string, extra map[string]string) []string {
	t.Helper()
	idx, err := LoadNVD(filepath.Join("testdata", "nvd_bmc_dsm.json"))
	if err != nil {
		t.Fatalf("LoadNVD: %v", err)
	}
	p, v, e, ok := Subject(product, raw, extra)
	if !ok {
		return nil
	}
	var ids []string
	for _, f := range idx.Lookup(p, v, e) {
		if !slices.Contains(ids, f.AdvisoryID) {
			ids = append(ids, f.AdvisoryID)
		}
	}
	slices.Sort(ids)
	return ids
}

func TestLookupIDRACByGeneration(t *testing.T) {
	for _, tc := range []struct {
		firmware, model string
		want            []string
	}{
		// 2.65.65.65 is iDRAC7's fix and still short of iDRAC8's.
		{"2.65.65.65", "12G Modular", nil},
		{"2.65.65.65", "13G Monolithic", []string{"CVE-2019-3764"}},
		{"7.00.00.180", "16G Monolithic", []string{"CVE-2025-22397"}},
		{"7.00.00.181", "15G Monolithic", nil},
		// No model: 3.x and later can only be iDRAC9; 2.x could be 7 or 8.
		{"3.30.30.30", "", []string{"CVE-2019-3764"}},
		{"2.60.60.60", "", nil},
	} {
		var extra map[string]string
		if tc.model != "" {
			extra = map[string]string{"model": tc.model}
		}
		if got := bmcDSMIDs(t, "dell-idrac", tc.firmware, extra); !slices.Equal(got, tc.want) {
			t.Errorf("%s (%q): got %v, want %v", tc.firmware, tc.model, got, tc.want)
		}
	}
	if _, _, _, ok := Subject("dell-idrac", "2.60.60.60", nil); ok {
		t.Error("iDRAC 2.x with no model must not be looked up")
	}
}

func TestLookupILO4(t *testing.T) {
	if got := bmcDSMIDs(t, "hp-ilo4", "2.81", nil); !slices.Equal(got, []string{"CVE-2023-28083"}) {
		t.Errorf("2.81: got %v", got)
	}
	if got := bmcDSMIDs(t, "hp-ilo4", "2.82", nil); got != nil {
		t.Errorf("2.82: got %v, want none", got)
	}
}

func TestLookupSynologyBuildAndUpdate(t *testing.T) {
	for _, tc := range []struct {
		version, update string
		want            []string
	}{
		{"7.2.1-69057", "6", []string{"CVE-2025-1021"}},
		{"7.2.1-69057", "7", nil},
		{"7.2.2-72806", "2", []string{"CVE-2025-1021"}},
		{"7.2.2-72806", "3", nil},
		// 7.2 isn't in any of the three ranges.
		{"7.2-64570", "4", nil},
		{"7.1.1-42962", "7", []string{"CVE-2025-1021"}},
		// No Update known (an older inventory): read as Update 0.
		{"7.1.1-42962", "", []string{"CVE-2025-1021"}},
	} {
		var extra map[string]string
		if tc.update != "" {
			extra = map[string]string{"update": tc.update}
		}
		if got := bmcDSMIDs(t, "synology-dsm", tc.version, extra); !slices.Equal(got, tc.want) {
			t.Errorf("%s Update %s: got %v, want %v", tc.version, tc.update, got, tc.want)
		}
	}
}

func TestFoldSynologyBuilds(t *testing.T) {
	for in, want := range map[string]string{
		"7.2.1-69057-6":            "7.2.1.69057.6",
		"7.2-64570-4":              "7.2.0.64570.4",
		"6.2.4-25556.4":            "6.2.4.25556.4",
		"7.2.2-72806":              "7.2.2.72806.0",
		"до 7.2.1-69057-6":         "до 7.2.1.69057.6",
		"7.3":                      "7.3",
		"cpe:2.3:o:x:y:4.3-3810:1": "cpe:2.3:o:x:y:4.3.0.3810.0:1",
	} {
		if got := foldSynologyBuilds(in); got != want {
			t.Errorf("foldSynologyBuilds(%q) = %q, want %q", in, got, want)
		}
	}
	r := versionRange{Lo: []int{7, 2, 1, 69057}, LoInclusive: true, Hi: []int{7, 2, 1, 69057, 7}}
	if got := rangeText("synology-dsm", r); got != ">=7.2.1-69057, <7.2.1-69057-7" {
		t.Errorf("rangeText = %q", got)
	}
}
