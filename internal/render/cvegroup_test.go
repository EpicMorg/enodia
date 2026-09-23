// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/EpicMorg/enodia/internal/cve"
)

// Shaped like the real data for CVE-2023-22515: BDU's one advisory plus
// NVD's two findings for it, one per CPE (confluence_server and
// confluence_data_center).
func confluence22515() []cve.Finding {
	nvd := func(cpe string) cve.Finding {
		return cve.Finding{Source: "nvd", AdvisoryID: "CVE-2023-22515", CVEIDs: []string{"CVE-2023-22515"},
			Title: "Atlassian has been made aware of an issue", MatchedName: cpe,
			Severity: "CRITICAL", CVSS: cve.CVSS{Version: "3.1", Score: 10, Severity: "CRITICAL"}}
	}
	return []cve.Finding{
		nvd("cpe:2.3:a:atlassian:confluence_server:*:*:*:*:*:*:*:*"),
		{Source: "bdu", AdvisoryID: "BDU:2023-06364", CVEIDs: []string{"CVE-2023-22515"},
			Title: "Уязвимость веб-сервера Atlassian Confluence Server",
			CVSS:  cve.CVSS{Version: "3.0", Score: 9.8, Severity: "CRITICAL"}},
		nvd("cpe:2.3:a:atlassian:confluence_data_center:*:*:*:*:*:*:*:*"),
	}
}

func TestGroupCVEsMergesSourcesAndCPEs(t *testing.T) {
	groups := groupCVEs(confluence22515())
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1 for one CVE", len(groups))
	}
	g := groups[0]
	if g.title != "Уязвимость веб-сервера Atlassian Confluence Server" {
		t.Errorf("title %q: BDU's Russian text should win over NVD's English", g.title)
	}
	if g.rating.Version != "3.1" || g.rating.Score != 10 {
		t.Errorf("rating %+v: NVD's own score should win over BDU's", g.rating)
	}
	if len(g.bduIDs) != 1 || g.bduIDs[0] != "BDU:2023-06364" || len(g.cveIDs) != 1 {
		t.Errorf("got cveIDs %v bduIDs %v", g.cveIDs, g.bduIDs)
	}
	if strings.Join(g.tags, ",") != "nvd,bdu" {
		t.Errorf("got tags %v, want both sources once each", g.tags)
	}
	if got := distinctCVECount(confluence22515()); got != 1 {
		t.Errorf("distinctCVECount = %d, want 1 (three findings, one CVE)", got)
	}
}

// NVD-only: English text is all there is; BDU-only: BDU's rating is used.
func TestGroupCVEsFallsBackPerSource(t *testing.T) {
	groups := groupCVEs([]cve.Finding{
		{Source: "nvd", AdvisoryID: "CVE-2026-1", CVEIDs: []string{"CVE-2026-1"}, Title: "english only",
			CVSS: cve.CVSS{Version: "3.1", Score: 5, Severity: "MEDIUM"}},
		{Source: "bdu", AdvisoryID: "BDU:2026-2", CVEIDs: []string{"CVE-2026-2"}, Title: "только русский",
			CVSS: cve.CVSS{Version: "3.0", Score: 7.5, Severity: "HIGH"}},
	})
	if groups[0].key != "CVE-2026-2" || groups[0].rating.Score != 7.5 || groups[0].title != "только русский" {
		t.Errorf("first group %+v, want the BDU-only HIGH one first", groups[0])
	}
	if groups[1].title != "english only" {
		t.Errorf("second group title %q", groups[1].title)
	}
}

// Most severe first; equal scores newest first, compared numerically
// (CVE-2026-85706 is newer than CVE-2026-9807).
func TestGroupCVEsSortOrder(t *testing.T) {
	f := func(id string, score float64, sev string) cve.Finding {
		return cve.Finding{Source: "nvd", AdvisoryID: id, CVEIDs: []string{id}, CVSS: cve.CVSS{Version: "3.1", Score: score, Severity: sev}}
	}
	groups := groupCVEs([]cve.Finding{
		f("CVE-2025-100", 5, "MEDIUM"),
		f("CVE-2026-9807", 9.8, "CRITICAL"),
		{Source: "bdu", AdvisoryID: "BDU:2026-1", Severity: "Данные уточняются"}, // no rating, no CVE
		f("CVE-2026-85706", 9.8, "CRITICAL"),
	})
	var got []string
	for _, g := range groups {
		got = append(got, g.key)
	}
	want := "CVE-2026-85706,CVE-2026-9807,CVE-2025-100,BDU:2026-1"
	if strings.Join(got, ",") != want {
		t.Fatalf("got %v, want %s", got, want)
	}
	if groups[3].ratingText() != "Данные уточняются" {
		t.Errorf("unrated group should fall back to the source's own text, got %q", groups[3].ratingText())
	}
}

func TestCVEGroupRatingText(t *testing.T) {
	for _, c := range []struct {
		r    cve.CVSS
		want string
	}{
		{cve.CVSS{Version: "3.1", Score: 9.8, Severity: "CRITICAL"}, "CRITICAL · CVSS 3.1 9.8"},
		{cve.CVSS{Version: "2.0", Score: 10, Severity: "HIGH"}, "HIGH · CVSS 2.0 10"},
		{cve.CVSS{Version: "3.1", Severity: "CRITICAL"}, "CRITICAL"}, // level without a score
	} {
		if got := (cveGroup{rating: c.r}).ratingText(); got != c.want {
			t.Errorf("%+v: got %q, want %q", c.r, got, c.want)
		}
	}
}

// One modal line per CVE, with all three kinds of link on it, and the
// CVES cell counting CVEs, not findings.
func TestHTMLCVEModalOneLinePerCVE(t *testing.T) {
	r := sampleReport()
	i := findAssessmentIndex(r.Assessments, "confluence-a")
	r.Assessments[i].CVEs = confluence22515()
	var buf bytes.Buffer
	if err := HTML(&buf, r, HTMLOptions{View: ViewCompact}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	if n := strings.Count(out, `<li class="mb-2">`); n != 1 {
		t.Fatalf("got %d modal lines, want 1 for one CVE", n)
	}
	for _, want := range []string{
		`href="https://nvd.nist.gov/vuln/detail/CVE-2023-22515"`,
		`href="https://www.cve.org/CVERecord?id=CVE-2023-22515"`,
		`href="https://bdu.fstec.ru/vul/2023-06364"`,
		"CRITICAL · CVSS 3.1 10",
		"Уязвимость веб-сервера Atlassian Confluence Server",
		`<td>1 <a href="#enodia-cve-modal-compact-`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}
