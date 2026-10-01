// SPDX-License-Identifier: AGPL-3.0-or-later

package version

import "testing"

func TestCompareRPM(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"0:1.0~rc1-1", "0:1.0-1", -1},
		{"0:1.0-1", "0:1.0^git1-1", -1},
		{"0:1.0^git1-1", "0:1.0.1-1", -1},
		{"1:1.0-1", "0:2.0-1", 1}, // epoch wins
		{"1.0-1", "0:1.0-1", 0},   // a missing epoch is 0
		{"0:1.01-1", "0:1.1-1", 0},
		{"0:1.0a-1", "0:1.0-1", 1},
		{"0:5.14.0-427.13.1.el9_4", "0:5.14.0-427.13.1.el9_4.1", -1},
		{"0:1.0-1.el9", "0:1.0-1.el9_1", -1},
	} {
		if got := CompareRPM(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareRPM(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		if got := CompareRPM(tc.b, tc.a); got != -tc.want {
			t.Errorf("CompareRPM(%q, %q) = %d, want %d", tc.b, tc.a, got, -tc.want)
		}
	}
}

// testdata/rpm_compare.txt is ~4800 pairs of real fixed versions from the
// RHEL 9, Oracle Linux 9 and AlmaLinux 9 OVAL files, each with the order
// python3-rpm's rpm.labelCompare gave inside a rockylinux:9 container.
func TestCompareRPMMatchesLabelCompare(t *testing.T) {
	checkVectors(t, "testdata/rpm_compare.txt", CompareRPM, 4800)
}
