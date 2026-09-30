// SPDX-License-Identifier: AGPL-3.0-or-later

package version

import "strings"

// CompareDebian orders two Debian package versions ("[epoch:]upstream[-revision]")
// exactly the way dpkg does (dpkg's own verrevcmp, lib/dpkg/version.c),
// returning -1, 0 or 1. Unlike Compare it never fails: every string is a
// valid dpkg version to dpkg's comparison, which is what the Debian
// Security Tracker's fixed versions are written against — "1.2~rc1"
// sorts before "1.2", "2.3.2-2" before "2.3.2-2+b1", "1:0.9" after "9.9".
func CompareDebian(a, b string) int {
	ae, au, ar := splitDebian(a)
	be, bu, br := splitDebian(b)
	if c := verrevcmp(ae, be); c != 0 {
		return c
	}
	if c := verrevcmp(au, bu); c != 0 {
		return c
	}
	return verrevcmp(ar, br)
}

// splitDebian cuts a version into epoch, upstream version and revision.
// The epoch is everything before the first ':', the revision everything
// after the last '-' — dpkg's own parseversion rule.
func splitDebian(v string) (epoch, upstream, revision string) {
	v = strings.TrimSpace(v)
	epoch = "0"
	if e, rest, ok := strings.Cut(v, ":"); ok {
		epoch, v = e, rest
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// debOrder is dpkg's order(): digits and the end of the string weigh 0,
// letters their own code, '~' sorts before everything (even the end of
// the string), and any other character after every letter.
func debOrder(c byte) int {
	switch {
	case isDigit(c):
		return 0
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return int(c)
	case c == '~':
		return -1
	case c != 0:
		return int(c) + 256
	default:
		return 0
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func verrevcmp(a, b string) int {
	at := func(s string, i int) byte {
		if i < len(s) {
			return s[i]
		}
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := debOrder(at(a, i)), debOrder(at(b, j))
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		for at(a, i) == '0' {
			i++
		}
		for at(b, j) == '0' {
			j++
		}
		firstDiff := 0
		for isDigit(at(a, i)) && isDigit(at(b, j)) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if isDigit(at(a, i)) {
			return 1
		}
		if isDigit(at(b, j)) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
