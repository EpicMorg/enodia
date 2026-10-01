// SPDX-License-Identifier: AGPL-3.0-or-later

package version

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestCompareDebian(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.2~rc1", "1.2", -1},
		{"2.3.2-2", "2.3.2-2+b1", -1}, // binNMU
		{"1:0.9", "9.9", 1},           // epoch wins
		{"0:1.0", "1.0", 0},           // an explicit zero epoch is no epoch
		{"1.0~", "1.0", -1},
		{"1.0~~", "1.0~", -1},
		{"1.001", "1.1", 0}, // leading zeros don't count
		{"1.0-1.2", "1.0-1.10", -1},
		{"3.5.7-1~deb13u2", "3.5.7-1~deb13u3", -1},
		{"6.12.107-1", "6.12.111-1", -1},
		{"1.0a", "1.0+", -1}, // letters before every other character
	} {
		if got := CompareDebian(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareDebian(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		if got := CompareDebian(tc.b, tc.a); got != -tc.want {
			t.Errorf("CompareDebian(%q, %q) = %d, want %d", tc.b, tc.a, got, -tc.want)
		}
	}
}

// testdata/debian_compare.txt is ~4000 pairs of real versions from the
// Debian Security Tracker's own JSON, each with the order python3-apt's
// apt_pkg.version_compare (libapt's implementation of dpkg's rule) gave.
func TestCompareDebianMatchesAptPkg(t *testing.T) {
	checkVectors(t, "testdata/debian_compare.txt", CompareDebian, 4000)
}

// checkVectors runs cmp over a "a b want" file, one pair per line.
func checkVectors(t *testing.T, path string, cmp func(a, b string) int, atLeast int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			t.Fatalf("bad line %q", line)
		}
		want, err := strconv.Atoi(fields[2])
		if err != nil {
			t.Fatalf("bad line %q", line)
		}
		if got := cmp(fields[0], fields[1]); got != want {
			t.Errorf("compare(%q, %q) = %d, reference says %d", fields[0], fields[1], got, want)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n < atLeast {
		t.Fatalf("only %d vectors read", n)
	}
}
