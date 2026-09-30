// SPDX-License-Identifier: AGPL-3.0-or-later

package version

import "testing"

func TestCompareAPK(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.0_rc1-r0", "1.0-r0", -1},
		{"1.0_alpha-r0", "1.0_beta-r0", -1},
		{"1.0_p1-r0", "1.0-r0", 1},
		{"1.0_git20240101-r0", "1.0-r0", 1},
		{"1.0a-r0", "1.0-r0", 1},
		// apk reads one letter after a number; a second one ends the
		// comparison as invalid, so these are equal to apk itself.
		{"0.9.8zh-r0", "0.9.8zg-r0", 0},
		{"1.0-r1", "1.0-r0", 1},
		{"1.0.0-r0", "1.0-r0", 1},
		{"1.01-r0", "1.1-r0", -1},
		{"1.2.3_pre2-r0", "1.2.3_pre10-r0", -1},
		{"3.3.2-r0", "3.3.2-r0", 0},
	} {
		if got := CompareAPK(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareAPK(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		if got := CompareAPK(tc.b, tc.a); got != -tc.want {
			t.Errorf("CompareAPK(%q, %q) = %d, want %d", tc.b, tc.a, got, -tc.want)
		}
	}
}

// testdata/apk_compare.txt is ~5300 pairs of real fixed versions from
// Alpine's secdb (v3.20 and v3.22, main and community), each with the
// order apk-tools 2.14.4's own `apk version -t` gave inside alpine:3.20.0.
func TestCompareAPKMatchesApkTools(t *testing.T) {
	checkVectors(t, "testdata/apk_compare.txt", CompareAPK, 5200)
}
