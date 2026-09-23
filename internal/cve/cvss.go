// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"regexp"
	"strconv"
	"strings"
)

// cvss is one source's structured CVSS rating for a Finding: the metric
// version it came from, its base score, and its qualitative severity in
// CVSS's own vocabulary (CRITICAL, HIGH, MEDIUM, LOW, NONE).
type cvss struct {
	version  string
	score    float64
	severity string
}

// cvssPreference is the order a rating is picked in when a record
// carries several: CVSS 3.x first, because it's the one version both
// sources and nearly every CVE carry — so every score in one list is on
// the same scale and sorts meaningfully — then 4.0, then 2.0. Measured
// against the real exports: of BDU's 96,135 entries 95,854 carry 2.0,
// 78,525 a 3.x rating and only 395 a 4.0 one; NVD's 2026 file carries
// 3.1 on 55,942 records, 4.0 on 18,587.
var cvssPreference = []string{"3.1", "3.0", "4.0", "2.0"}

func pickCVSS(byVersion map[string]cvss) (cvss, bool) {
	for _, v := range cvssPreference {
		if c, ok := byVersion[v]; ok {
			return c, true
		}
	}
	return cvss{}, false
}

// bduSeverityPattern matches one rating inside BDU's free-text severity
// field, e.g. "Критический уровень опасности (базовая оценка CVSS 3.0
// составляет 9,8)". Built against every one of the real export's 96,135
// entries, which parse with nothing left over; the variants that real
// data needed beyond that example: "Нет опасности" as a level (sometimes
// without "уровень опасности" after it), "оценка" without "базовая" on
// CVSS 4.0 ratings, and a decimal point instead of a comma in the score.
var bduSeverityPattern = regexp.MustCompile(`(Критический|Высокий|Средний|Низкий|Нет опасности)(?: уровень опасности)? \((?:базовая )?оценка CVSS (\d\.\d) составляет (\d+(?:[.,]\d+)?)\)`)

var bduSeverityLevels = map[string]string{
	"Критический":   "CRITICAL",
	"Высокий":       "HIGH",
	"Средний":       "MEDIUM",
	"Низкий":        "LOW",
	"Нет опасности": "NONE",
}

// parseBDUSeverity extracts the preferred CVSS rating from BDU's severity
// text. BDU lists one rating per CVSS version, one per line.
func parseBDUSeverity(text string) (cvss, bool) {
	byVersion := map[string]cvss{}
	for _, m := range bduSeverityPattern.FindAllStringSubmatch(text, -1) {
		score, err := strconv.ParseFloat(strings.Replace(m[3], ",", ".", 1), 64)
		if err != nil {
			continue
		}
		if _, seen := byVersion[m[2]]; !seen {
			byVersion[m[2]] = cvss{version: m[2], score: score, severity: bduSeverityLevels[m[1]]}
		}
	}
	return pickCVSS(byVersion)
}
