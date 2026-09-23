// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// nvdCPEMatch, nvdNode, nvdConfiguration, nvdCVSSData, nvdCVSSMetric,
// nvdMetrics, nvdDescription, nvdCVE and nvdVulnerability mirror just the
// fields this project reads out of one NVD API 2.0 CVE record (the exact
// shape https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema
// describes, and the shape NVD's own yearly bulk exports use too —
// confirmed live both ways: fetching CVE-2023-22515 from
// services.nvd.nist.gov/rest/json/cves/2.0 and grepping the same record
// out of nvdcve-2.0-2023.json.gz gives the identical configurations
// shape). encoding/json ignores fields this struct doesn't name, so the
// many fields not listed here (references, weaknesses, cisaExploitAdd,
// ...) are simply skipped, not an omission that needs revisiting.
type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type nvdNode struct {
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdConfiguration struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdCVSSData struct {
	BaseSeverity string `json:"baseSeverity"`
}

// BaseSeverity is checked in two places: nested under CVSSData for the
// v3.x metric shape, and top-level on the metric itself for the older
// v2 shape — confirmed live against real records of each kind.
type nvdCVSSMetric struct {
	CVSSData     nvdCVSSData `json:"cvssData"`
	BaseSeverity string      `json:"baseSeverity"`
}

type nvdMetrics struct {
	CVSSMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdCVSSMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []nvdCVSSMetric `json:"cvssMetricV2"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdCVE struct {
	ID             string             `json:"id"`
	VulnStatus     string             `json:"vulnStatus"`
	Descriptions   []nvdDescription   `json:"descriptions"`
	Metrics        nvdMetrics         `json:"metrics"`
	Configurations []nvdConfiguration `json:"configurations"`
}

type nvdVulnerability struct {
	CVE nvdCVE `json:"cve"`
}

// LoadNVD builds an Index from path, which may be a single file (raw
// .json, .json.gz, or .json.zip containing exactly one .json member) or a
// directory containing any number of them — NVD publishes one archive per
// calendar year (nvdcve-2.0-<year>.json.gz, confirmed live still served
// alongside the newer live API, see docs/DECISIONS.md D31), so an operator
// who downloads several years at once just points cve.nvd.path at the
// directory they landed in.
//
// This always streams: encoding/json.Decoder token by token into the
// top-level "vulnerabilities" array, decoding one CVE record at a time —
// never json.Unmarshal on the whole file, for the same reason LoadBDU
// never calls xml.Unmarshal on the whole export.
func LoadNVD(path string) (*Index, error) {
	files, err := resolveNVDFiles(path)
	if err != nil {
		return nil, err
	}

	cpeToProduct := make(map[cpeName]string, len(productCPENames)*2)
	for product, names := range productCPENames {
		for _, n := range names {
			cpeToProduct[n] = product
		}
	}

	idx := &Index{byProduct: make(map[string][]Finding)}
	for _, f := range files {
		if err := loadNVDFile(f, idx, cpeToProduct); err != nil {
			return nil, err
		}
	}
	return idx, nil
}

// resolveNVDFiles expands path into the list of files to parse: itself, if
// it names a file, or every .json/.json.gz/.json.zip entry directly inside
// it (not recursively — NVD's own yearly archives are flat), sorted for a
// deterministic parse order, if it names a directory.
func resolveNVDFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.IsDir() {
		return []string{path}, nil
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".json.gz") || strings.HasSuffix(name, ".json.zip") {
			files = append(files, filepath.Join(path, e.Name()))
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s: no .json/.json.gz/.json.zip files found", path)
	}
	sort.Strings(files)
	return files, nil
}

func loadNVDFile(path string, idx *Index, cpeToProduct map[cpeName]string) error {
	r, cleanup, err := openNVDSource(path)
	if err != nil {
		return err
	}
	defer cleanup()

	dec := json.NewDecoder(r)
	if err := decodeNVDStream(dec, idx, cpeToProduct); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	return nil
}

// decodeNVDStream walks path's top-level JSON object looking for the
// "vulnerabilities" key (present exactly once, before any per-CVE data),
// then decodes that array one element at a time.
func decodeNVDStream(dec *json.Decoder, idx *Index, cpeToProduct map[cpeName]string) error {
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok || key != "vulnerabilities" {
			continue
		}

		arr, err := dec.Token()
		if err != nil {
			return err
		}
		if delim, ok := arr.(json.Delim); !ok || delim != '[' {
			return fmt.Errorf(`expected an array after "vulnerabilities"`)
		}
		for dec.More() {
			var item nvdVulnerability
			if err := dec.Decode(&item); err != nil {
				return err
			}
			indexNVDVuln(idx, item.CVE, cpeToProduct)
		}
		_, err = dec.Token() // the closing ']'
		return err
	}
}

// indexNVDVuln matches v's configurations against cpeToProduct — the
// reverse of productCPENames — and records one Finding per matching
// cpeMatch entry.
//
// NVD's configurations express node-level AND/OR/NOT boolean logic across
// multiple CPEs (e.g. "vulnerable only if product X AND library Y are both
// present"), which this project doesn't attempt to reconstruct: every
// individual `vulnerable: true` cpeMatch entry for a product this table
// knows about is recorded on its own, regardless of which node or operator
// it came from. An enodia probe only ever reports one product and one
// version per observation, so there's no second CPE to evaluate a real
// AND against anyway — the same reporting bias D30 already accepts for
// BDU's own overlapping-branch limitation applies here for the same
// reason: a spurious match that turns out to not apply is a prompt to
// double-check, not a missed vulnerability.
func indexNVDVuln(idx *Index, v nvdCVE, cpeToProduct map[cpeName]string) {
	if v.VulnStatus == "Rejected" {
		return
	}

	var title string
	for _, d := range v.Descriptions {
		if d.Lang == "en" {
			title = d.Value
			break
		}
	}
	severity := nvdSeverity(v.Metrics)

	for _, cfg := range v.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				vendor, product, ok := cpeVendorProduct(m.Criteria)
				if !ok {
					continue
				}
				enodiaProduct, ok := cpeToProduct[cpeName{vendor, product}]
				if !ok {
					continue
				}
				rng, ok := parseNVDRange(m)
				if !ok {
					continue
				}
				idx.byProduct[enodiaProduct] = append(idx.byProduct[enodiaProduct], Finding{
					Source:      "nvd",
					AdvisoryID:  v.ID,
					CVEIDs:      []string{v.ID},
					Title:       title,
					Severity:    severity,
					MatchedName: m.Criteria,
					RangeText:   rng.String(),
					Edition:     cpeSWEdition(m.Criteria),
					rng:         rng,
				})
			}
		}
	}
}

// nvdSeverity picks the first available CVSS baseSeverity, preferring the
// newest metric version present — the same "best available, not every
// available" choice most CVE tooling makes when a record carries more
// than one CVSS scoring.
func nvdSeverity(m nvdMetrics) string {
	for _, list := range [][]nvdCVSSMetric{m.CVSSMetricV31, m.CVSSMetricV30} {
		if len(list) > 0 && list[0].CVSSData.BaseSeverity != "" {
			return list[0].CVSSData.BaseSeverity
		}
	}
	if len(m.CVSSMetricV2) > 0 {
		return m.CVSSMetricV2[0].BaseSeverity
	}
	return ""
}

// parseNVDRange turns one cpeMatch's version-bound fields into a
// versionRange. Confirmed live that a real cpeMatch entry can carry zero,
// one, or two of the four bound fields — CVE-2023-22515's own Confluence
// entries each carry exactly versionStartIncluding+versionEndExcluding,
// but other real CVEs carry only a start (still vulnerable in every later
// release, no fix published yet) or embed an exact version directly in
// the CPE string's own version field with no bound fields at all (e.g.
// CVE-2019-14994's "jira_service_desk:4.4.0" entries). An entry with
// neither bounds nor a version is rejected — see the comment below.
func parseNVDRange(m nvdCPEMatch) (versionRange, bool) {
	var r versionRange
	switch {
	case m.VersionStartIncluding != "":
		p, ok := cleanVersionParts(m.VersionStartIncluding)
		if !ok {
			return versionRange{}, false
		}
		r.Lo, r.LoInclusive = p, true
	case m.VersionStartExcluding != "":
		p, ok := cleanVersionParts(m.VersionStartExcluding)
		if !ok {
			return versionRange{}, false
		}
		r.Lo, r.LoInclusive = p, false
	}
	switch {
	case m.VersionEndIncluding != "":
		p, ok := cleanVersionParts(m.VersionEndIncluding)
		if !ok {
			return versionRange{}, false
		}
		r.Hi, r.HiInclusive = p, true
	case m.VersionEndExcluding != "":
		p, ok := cleanVersionParts(m.VersionEndExcluding)
		if !ok {
			return versionRange{}, false
		}
		r.Hi, r.HiInclusive = p, false
	}

	if r.Lo == nil && r.Hi == nil {
		// No bound fields and no specific version in the CPE string either
		// ("*"): dropped, not read as "every version, forever". D31 first
		// shipped the opposite, as a false-positive-over-a-silent-miss
		// call; against the real exports it turned out to be almost all
		// noise — of Apache httpd 2.4.58's eleven such matches, ten were
		// CVEs from 1999-2008, and 64 of macOS 14.4's 67 were from
		// 1999-2016. NVD's "*" there meant every version that existed when
		// the CVE was analyzed, not every version ever released after it.
		// The cost, accepted: the rare genuinely unfixed-yet CVE recorded
		// this way isn't reported (see docs/DECISIONS.md D33).
		v := cpeVersionField(m.Criteria)
		if v == "" {
			return versionRange{}, false
		}
		p, ok := cleanVersionParts(v)
		if !ok {
			return versionRange{}, false
		}
		r.Lo, r.LoInclusive = p, true
		r.Hi, r.HiInclusive = p, true
	}
	return r, true
}

// cpeVendorProduct extracts the vendor and product fields (the 4th and
// 5th colon-separated components) of a CPE 2.3 formatted string, e.g.
// "atlassian", "confluence_server" from
// "cpe:2.3:a:atlassian:confluence_server:*:*:*:*:*:*:*:*".
func cpeVendorProduct(criteria string) (vendor, product string, ok bool) {
	fields := splitCPE(criteria)
	if len(fields) < 5 || fields[0] != "cpe" {
		return "", "", false
	}
	return fields[3], fields[4], true
}

// cpeVersionField extracts the version field (the 6th colon-separated
// component) of a CPE 2.3 formatted string, or "" when it's the
// wildcard/not-applicable placeholder ("*"/"-") rather than a literal
// version.
func cpeVersionField(criteria string) string {
	fields := splitCPE(criteria)
	if len(fields) < 6 {
		return ""
	}
	v := fields[5]
	if v == "*" || v == "-" {
		return ""
	}
	return v
}

// cpeSWEdition extracts the sw_edition field (the 10th colon-separated
// component) of a CPE 2.3 formatted string, or "" when it's the
// wildcard/not-applicable placeholder. GitLab's CVE configurations are
// where this was confirmed to carry a real restriction ("community" vs
// "enterprise"); other products use it for release channels ("lts"),
// which Lookup only ever compares against an edition a probe actually
// reported, so it never filters them.
func cpeSWEdition(criteria string) string {
	fields := splitCPE(criteria)
	if len(fields) < 10 {
		return ""
	}
	e := fields[9]
	if e == "*" || e == "-" {
		return ""
	}
	return e
}

// splitCPE splits a CPE 2.3 formatted string on ':', honoring '\'-escaped
// colons within a component (the CPE 2.3 spec's own escaping rule) so a
// component that legitimately contains one doesn't fracture the field
// count — none of the products this package maps need one today, but a
// naive strings.Split would silently mis-split if one ever did.
func splitCPE(s string) []string {
	var fields []string
	var cur strings.Builder
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == ':':
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	fields = append(fields, cur.String())
	return fields
}

func openNVDSource(path string) (io.Reader, func(), error) {
	switch lower := strings.ToLower(path); {
	case strings.HasSuffix(lower, ".gz"):
		f, err := os.Open(path)
		if err != nil {
			return nil, nil, fmt.Errorf("opening %s: %w", path, err)
		}
		gz, err := gzip.NewReader(f)
		if err != nil {
			_ = f.Close()
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
		return gz, func() { _ = gz.Close(); _ = f.Close() }, nil
	case strings.HasSuffix(lower, ".zip"):
		return openZipJSON(path)
	default:
		f, err := os.Open(path)
		if err != nil {
			return nil, nil, fmt.Errorf("opening %s: %w", path, err)
		}
		return f, func() { _ = f.Close() }, nil
	}
}

func openZipJSON(path string) (io.Reader, func(), error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, nil, fmt.Errorf("opening %s: %w", path, err)
	}
	var member *zip.File
	for _, f := range zr.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			member = f
			break
		}
	}
	if member == nil {
		_ = zr.Close()
		return nil, nil, fmt.Errorf("%s: no .json member found in zip", path)
	}
	rc, err := member.Open()
	if err != nil {
		_ = zr.Close()
		return nil, nil, fmt.Errorf("%s: opening %s: %w", path, member.Name, err)
	}
	return rc, func() { _ = rc.Close(); _ = zr.Close() }, nil
}
