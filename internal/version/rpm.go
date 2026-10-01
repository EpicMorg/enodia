// SPDX-License-Identifier: AGPL-3.0-or-later

package version

import (
	"strconv"
	"strings"
)

// CompareRPM orders two RPM "[epoch:]version-release" strings the way rpm
// itself does (rpmvercmp in rpmio/rpmvercmp.c, compared epoch, then
// version, then release — rpm.labelCompare), returning -1, 0 or 1. It
// includes rpm 4.10+'s '~' (sorts before everything, "1.0~rc1" < "1.0")
// and rpm 4.15+'s '^' (sorts after the base version, but before any
// further release of it: "1.0" < "1.0^git1" < "1.0.1"). A missing epoch
// is 0, as in the OVAL data RHEL-family vendors publish ("0:1.2-3.el9").
func CompareRPM(a, b string) int {
	ae, av, ar := splitRPM(a)
	be, bv, br := splitRPM(b)
	if c := compareEpoch(ae, be); c != 0 {
		return c
	}
	if c := rpmvercmp(av, bv); c != 0 {
		return c
	}
	return rpmvercmp(ar, br)
}

func splitRPM(s string) (epoch, ver, rel string) {
	s = strings.TrimSpace(s)
	if e, rest, ok := strings.Cut(s, ":"); ok {
		epoch, s = e, rest
	}
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		return epoch, s[:i], s[i+1:]
	}
	return epoch, s, ""
}

func compareEpoch(a, b string) int {
	an, _ := strconv.Atoi(a)
	bn, _ := strconv.Atoi(b)
	switch {
	case an < bn:
		return -1
	case an > bn:
		return 1
	}
	return 0
}

func isAlnum(c byte) bool { return isDigit(c) || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}

		ai, bj := byteAt(a, i), byteAt(b, j)
		if ai == '~' || bj == '~' {
			if ai != '~' {
				return 1
			}
			if bj != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		if ai == '^' || bj == '^' {
			switch {
			case i >= len(a):
				return -1
			case j >= len(b):
				return 1
			case ai != '^':
				return 1
			case bj != '^':
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}

		si, sj := i, j
		isNum := isDigit(a[i])
		if isNum {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isLetter(a[i]) {
				i++
			}
			for j < len(b) && isLetter(b[j]) {
				j++
			}
		}
		if sj == j {
			// Segments of different types: a number is newer than letters.
			if isNum {
				return 1
			}
			return -1
		}

		segA, segB := a[si:i], b[sj:j]
		if isNum {
			segA = strings.TrimLeft(segA, "0")
			segB = strings.TrimLeft(segB, "0")
			if len(segA) != len(segB) {
				if len(segA) > len(segB) {
					return 1
				}
				return -1
			}
		}
		if c := strings.Compare(segA, segB); c != 0 {
			return c
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i < len(a):
		return 1
	}
	return -1
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func byteAt(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}
