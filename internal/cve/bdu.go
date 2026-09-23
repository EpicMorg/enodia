// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Finding is one product/CVE match extracted from a BDU export, kept only
// for products productSoftNames maps. BDU's own free-text fields are
// carried through as-is (D7: facts, not a verdict) — Severity here is
// BDU's own published rating, not something this project computed.
type Finding struct {
	BDUID     string   // e.g. "BDU:2023-06364"
	CVEIDs    []string // e.g. ["CVE-2023-22515"]; may be empty — not every BDU entry cites one
	Title     string
	Severity  string // BDU's own free-text severity
	SoftName  string // the exact <soft><name> this range came from
	RangeText string // the original <version> text, kept for display
	FixStatus string

	rng bduRange
}

// Matches reports whether probed (a raw version string, as a probe
// reports it) falls inside this finding's range.
func (f Finding) Matches(probed string) bool {
	parts, ok := cleanVersionParts(probed)
	if !ok {
		return false
	}
	return f.rng.matches(parts)
}

// Index is a parsed, filtered BDU export: only the products
// productSoftNames knows about, nothing else — confirmed live the full
// export carries 90000+ entries across every vendor FSTEC tracks, the
// overwhelming majority of which enodia has no probe for at all and would
// just be dead weight to keep in memory or on disk.
//
// One real limitation, found live rather than guessed: a single <vul> can
// list several <soft> ranges for the very same product name, one per
// maintenance branch, each with its own fix version as the upper bound —
// confirmed against CVE-2023-22515's real Confluence entry ("от 8.0.0 до
// 8.3.3" / "8.4.3" / "8.5.2", one per branch). BDU's own data doesn't say
// which branch a range belongs to beyond the numbers themselves, so a
// widest-range match can flag an exact branch-fix version (8.3.3 here) as
// still vulnerable purely because it's numerically inside a wider
// *sibling* branch's range. Deliberately not "fixed": between silently
// under-reporting (a real miss) and occasionally telling someone to
// double-check a version that's actually already safe on its own branch,
// this project takes the side that doesn't risk a missed vulnerability.
type Index struct {
	byProduct map[string][]Finding
}

// Lookup returns every finding for product whose range contains probed.
func (idx *Index) Lookup(product, probed string) []Finding {
	if idx == nil {
		return nil
	}
	var out []Finding
	for _, f := range idx.byProduct[product] {
		if f.Matches(probed) {
			out = append(out, f)
		}
	}
	return out
}

// bduSoft and bduVul mirror just the fields this project reads out of a
// real <vul> element — confirmed live against the real export (see
// docs/DECISIONS.md D30). encoding/xml ignores elements this struct
// doesn't name, so the many fields not listed here (description,
// solution, sources, cwes, ...) are simply skipped, not an omission that
// needs revisiting.
type bduSoft struct {
	Name    string `xml:"name"`
	Vendor  string `xml:"vendor"`
	Version string `xml:"version"`
}

type bduIdentifier struct {
	Type string `xml:"type,attr"`
	ID   string `xml:",chardata"`
}

type bduVul struct {
	Identifier string          `xml:"identifier"`
	Name       string          `xml:"name"`
	Software   []bduSoft       `xml:"vulnerable_software>soft"`
	CVEs       []bduIdentifier `xml:"identifiers>identifier"`
	Severity   string          `xml:"severity"`
	FixStatus  string          `xml:"fix_status"`
}

// LoadBDU builds an Index from path, which may be a raw .xml file, a .zip
// containing exactly one .xml member, or a .tar.gz containing exactly one
// .xml member — confirmed live that BDU's own published export is a .zip
// wrapping one large .xml file; .tar.gz is supported for an operator who
// repackages it that way, not something BDU itself publishes.
//
// This always streams: encoding/xml.Decoder token by token, never a full
// Unmarshal, since the real export is several hundred MB — decoding it as
// one in-memory tree would multiply that many times over in Go's own XML
// object overhead. Only <vul> elements whose <vulnerable_software><soft>
// list contains a name productSoftNames maps are kept; everything else is
// decoded (encoding/xml has to look at every byte regardless) and then
// immediately discarded.
func LoadBDU(path string) (*Index, error) {
	r, cleanup, err := openBDUSource(path)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	softToProduct := make(map[string]string, len(productSoftNames)*2)
	for product, names := range productSoftNames {
		for _, name := range names {
			softToProduct[name] = product
		}
	}

	idx := &Index{byProduct: make(map[string][]Finding)}
	dec := xml.NewDecoder(r)
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "vul" {
			continue
		}
		var v bduVul
		if err := dec.DecodeElement(&v, &se); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		indexVul(idx, v, softToProduct)
	}
	return idx, nil
}

func indexVul(idx *Index, v bduVul, softToProduct map[string]string) {
	var cveIDs []string
	for _, id := range v.CVEs {
		if strings.EqualFold(id.Type, "CVE") {
			cveIDs = append(cveIDs, strings.TrimSpace(id.ID))
		}
	}

	for _, soft := range v.Software {
		product, ok := softToProduct[soft.Name]
		if !ok {
			continue
		}
		rng, ok := parseBDUVersion(soft.Version)
		if !ok {
			continue
		}
		idx.byProduct[product] = append(idx.byProduct[product], Finding{
			BDUID:     v.Identifier,
			CVEIDs:    cveIDs,
			Title:     v.Name,
			Severity:  v.Severity,
			SoftName:  soft.Name,
			RangeText: soft.Version,
			FixStatus: v.FixStatus,
			rng:       rng,
		})
	}
}

// openBDUSource returns a reader over the single .xml member of path,
// dispatching on its extension, plus a cleanup func that closes whatever
// it opened. The caller must call cleanup exactly once.
func openBDUSource(path string) (io.Reader, func(), error) {
	switch {
	case strings.HasSuffix(strings.ToLower(path), ".zip"):
		return openZipXML(path)
	case strings.HasSuffix(strings.ToLower(path), ".tar.gz") || strings.HasSuffix(strings.ToLower(path), ".tgz"):
		return openTarGzXML(path)
	default:
		f, err := os.Open(path)
		if err != nil {
			return nil, nil, fmt.Errorf("opening %s: %w", path, err)
		}
		return f, func() { _ = f.Close() }, nil
	}
}

func openZipXML(path string) (io.Reader, func(), error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, nil, fmt.Errorf("opening %s: %w", path, err)
	}
	var member *zip.File
	for _, f := range zr.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".xml") {
			member = f
			break
		}
	}
	if member == nil {
		_ = zr.Close()
		return nil, nil, fmt.Errorf("%s: no .xml member found in zip", path)
	}
	rc, err := member.Open()
	if err != nil {
		_ = zr.Close()
		return nil, nil, fmt.Errorf("%s: opening %s: %w", path, member.Name, err)
	}
	return rc, func() { _ = rc.Close(); _ = zr.Close() }, nil
}

func openTarGzXML(path string) (io.Reader, func(), error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("opening %s: %w", path, err)
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			_ = gz.Close()
			_ = f.Close()
			return nil, nil, fmt.Errorf("%s: no .xml member found in tar.gz", path)
		}
		if err != nil {
			_ = gz.Close()
			_ = f.Close()
			return nil, nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		if strings.HasSuffix(strings.ToLower(hdr.Name), ".xml") {
			return tr, func() { _ = gz.Close(); _ = f.Close() }, nil
		}
	}
}
