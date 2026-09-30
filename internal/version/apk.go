// SPDX-License-Identifier: AGPL-3.0-or-later

package version

import "strings"

// apk version tokens, in apk-tools' own order (src/version.c): a token
// type sorting later than the other side's at the same position makes
// that side the older version, except for a pre-release suffix.
const (
	apkInvalid = iota - 1
	apkDigitOrZero
	apkDigit
	apkLetter
	apkSuffix
	apkSuffixNo
	apkRevisionNo
	apkEnd
)

var (
	apkPreSuffixes  = []string{"alpha", "beta", "pre", "rc"}
	apkPostSuffixes = []string{"cvs", "svn", "git", "hg", "p"}
)

// CompareAPK orders two Alpine package versions ("1.2.3_rc1-r0") the way
// apk-tools 2.x does (apk_version_compare), returning -1, 0 or 1:
// _alpha < _beta < _pre < _rc < release < _cvs < _svn < _git < _hg < _p,
// one trailing letter sorts after the bare number ("1.0a" > "1.0"), and
// "-rN" is the package revision. Quirks included: a second letter ends the
// comparison, so apk itself calls "0.9.8zh" and "0.9.8zg" equal.
func CompareAPK(a, b string) int {
	at, bt := apkDigit, apkDigit
	av, bv := 0, 0
	for at == bt && at != apkEnd && at != apkInvalid && av == bv {
		av = apkGetToken(&at, &a)
		bv = apkGetToken(&bt, &b)
	}
	switch {
	case av < bv:
		return -1
	case av > bv:
		return 1
	case at == bt:
		return 0
	}
	// Leading components are equal: the longer version is newer, unless
	// what makes it longer is a pre-release suffix.
	if tt := at; at == apkSuffix && apkGetToken(&tt, &a) < 0 {
		return -1
	}
	if tt := bt; bt == apkSuffix && apkGetToken(&tt, &b) < 0 {
		return 1
	}
	switch {
	case at > bt:
		return -1
	case bt > at:
		return 1
	}
	return 0
}

func isLower(c byte) bool { return c >= 'a' && c <= 'z' }

func apkNextToken(typ *int, s *string) {
	n := apkInvalid
	switch {
	case len(*s) == 0:
		n = apkEnd
	case (*typ == apkDigit || *typ == apkDigitOrZero) && isLower((*s)[0]):
		n = apkLetter
	case *typ == apkLetter && isDigit((*s)[0]):
		n = apkDigit
	case *typ == apkSuffix && isDigit((*s)[0]):
		n = apkSuffixNo
	default:
		switch (*s)[0] {
		case '.':
			n = apkDigitOrZero
		case '_':
			n = apkSuffix
		case '-':
			if len(*s) > 1 && (*s)[1] == 'r' {
				n = apkRevisionNo
				*s = (*s)[1:]
			}
		}
		*s = (*s)[1:]
	}
	// A token may only go "back" in the order for these three steps: a
	// new dotted number after a number, a new suffix after a suffix's own
	// number, a number after a letter.
	backwardOK := n == apkDigitOrZero && *typ == apkDigit ||
		n == apkSuffix && *typ == apkSuffixNo ||
		n == apkDigit && *typ == apkLetter
	if n < *typ && !backwardOK {
		n = apkInvalid
	}
	*typ = n
}

func apkGetToken(typ *int, s *string) int {
	if len(*s) == 0 {
		*typ = apkEnd
		return 0
	}
	v, i, nt := 0, 0, apkInvalid
	str := *s
	switch *typ {
	case apkDigitOrZero, apkDigit, apkSuffixNo, apkRevisionNo:
		if *typ == apkDigitOrZero && str[0] == '0' {
			// Leading zeros after a dot: "1.01" sorts before "1.1".
			for i < len(str) && str[i] == '0' {
				i++
			}
			nt = apkDigit
			v = -i
			break
		}
		for i < len(str) && isDigit(str[i]) {
			v = v*10 + int(str[i]-'0')
			i++
		}
	case apkLetter:
		v = int(str[0])
		i = 1
	case apkSuffix:
		found := false
		for k, suf := range apkPreSuffixes {
			if strings.HasPrefix(str, suf) {
				v, i, found = k-len(apkPreSuffixes), len(suf), true
				break
			}
		}
		if !found {
			for k, suf := range apkPostSuffixes {
				if strings.HasPrefix(str, suf) {
					v, i, found = k, len(suf), true
					break
				}
			}
		}
		if !found {
			*typ = apkInvalid
			return -1
		}
	default:
		*typ = apkInvalid
		return -1
	}
	*s = str[i:]
	switch {
	case len(*s) == 0:
		*typ = apkEnd
	case nt != apkInvalid:
		*typ = nt
	default:
		apkNextToken(typ, s)
	}
	return v
}
