// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// testdata/sample.xml carries three real-shaped <vul> entries: a real
// Confluence/Jira one (BDU:2023-06364, the actual CVE-2023-22515 record —
// see bduversion.go's doc comment for why that specific CVE matters), one
// for a product (Schneider Electric Modicon Quantum) productSoftNames
// does not map at all, and one whose only <soft> has a garbage version
// ("9.3(7)") to confirm one bad range doesn't take down the whole parse.
func TestLoadBDUFromRawXML(t *testing.T) {
	idx, err := LoadBDU(filepath.Join("testdata", "sample.xml"))
	if err != nil {
		t.Fatalf("LoadBDU: %v", err)
	}

	confluence := idx.Lookup("confluence", "8.3.0", "")
	if len(confluence) != 3 {
		t.Fatalf("got %d confluence findings for 8.3.0, want 3 (three overlapping ranges share this version)", len(confluence))
	}
	for _, f := range confluence {
		if f.AdvisoryID != "BDU:2023-06364" {
			t.Errorf("got AdvisoryID %q", f.AdvisoryID)
		}
		if len(f.CVEIDs) != 1 || f.CVEIDs[0] != "CVE-2023-22515" {
			t.Errorf("got CVEIDs %+v, want [CVE-2023-22515]", f.CVEIDs)
		}
	}

	// 8.3.3 is Atlassian's own fix version for the 8.3.x branch — but it
	// still numerically falls inside the wider "до 8.4.3"/"до 8.5.2"
	// sibling-branch ranges, so it matches those two. This is the
	// documented widest-range limitation (see Index's doc comment), not a
	// bug: erring toward "double-check this" rather than a silent miss.
	if got := idx.Lookup("confluence", "8.3.3", ""); len(got) != 2 {
		t.Fatalf("got %d findings for 8.3.3, want 2 (matches the two wider sibling-branch ranges)", len(got))
	}
	// 8.5.2 is excluded by its own branch's range (exclusive upper bound)
	// and is not less than the other two branches' own (smaller) bounds,
	// so it matches none of the three.
	if got := idx.Lookup("confluence", "8.5.2", ""); len(got) != 0 {
		t.Fatalf("got %d findings for 8.5.2, want 0", len(got))
	}

	jira := idx.Lookup("jira", "8.1.0", "")
	if len(jira) != 1 {
		t.Fatalf("got %d jira findings for 8.1.0, want 1 (Jira Data Center's own range)", len(jira))
	}

	// Modicon Quantum isn't in productSoftNames at all; PostgreSQL's only
	// entry has an unparseable version ("9.3(7)") — both must be silently
	// absent, not present with a wrong/empty range, and must not have
	// broken parsing the rest of the file.
	if got := idx.Lookup("postgresql", "9.3.7", ""); len(got) != 0 {
		t.Errorf("got %d postgresql findings, want 0 (the only entry has an unparseable version)", len(got))
	}
}

func TestLoadBDUFromZip(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "sample.xml"))
	if err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(t.TempDir(), "sample.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("export/vulxml.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	idx, err := LoadBDU(zipPath)
	if err != nil {
		t.Fatalf("LoadBDU: %v", err)
	}
	if got := idx.Lookup("confluence", "8.3.0", ""); len(got) != 3 {
		t.Fatalf("got %d confluence findings via zip, want 3", len(got))
	}
}

func TestLoadBDUFromTarGz(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "sample.xml"))
	if err != nil {
		t.Fatal(err)
	}
	tgzPath := filepath.Join(t.TempDir(), "sample.tar.gz")
	f, err := os.Create(tgzPath)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "vulxml.xml", Size: int64(len(raw)), Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	idx, err := LoadBDU(tgzPath)
	if err != nil {
		t.Fatalf("LoadBDU: %v", err)
	}
	if got := idx.Lookup("confluence", "8.3.0", ""); len(got) != 3 {
		t.Fatalf("got %d confluence findings via tar.gz, want 3", len(got))
	}
}

func TestLoadBDUMissingFile(t *testing.T) {
	_, err := LoadBDU(filepath.Join(t.TempDir(), "does-not-exist.xml"))
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestLoadBDUZipWithNoXMLMember(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "empty.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("readme.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("not xml"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = LoadBDU(zipPath)
	if err == nil {
		t.Fatal("expected an error for a zip with no .xml member")
	}
}

// A nil Index (the state before any cve.bdu.path is configured) must
// answer Lookup safely, not panic — most enodia installs won't configure
// this at all.
func TestNilIndexLookupIsSafe(t *testing.T) {
	var idx *Index
	if got := idx.Lookup("confluence", "8.3.0", ""); got != nil {
		t.Fatalf("got %+v, want nil", got)
	}
}

// testdata/bdu_vendor.xml is synthetic, modeled on a real collision in
// the full export: "HTTP Server" appears under both Apache Software
// Foundation and Oracle Corp. (Oracle HTTP Server, its own 12.2.1.x
// numbering). Matching on name alone would hand Oracle's findings to
// every Apache httpd target whose version happens to fall in range.
func TestLoadBDUMatchesVendorNotJustName(t *testing.T) {
	idx, err := LoadBDU(filepath.Join("testdata", "bdu_vendor.xml"))
	if err != nil {
		t.Fatalf("LoadBDU: %v", err)
	}
	got := idx.Lookup("apache", "2.4.10", "")
	if len(got) != 1 || got[0].AdvisoryID != "BDU:2099-00010" {
		t.Fatalf("got %+v, want only the Apache Software Foundation entry", got)
	}
}

// testdata/bdu_edition.xml is synthetic, modeled on the real export's
// three separately listed Vault products ("Vault", "Vault Enterprise",
// "Vault Community Edition"). The edition-specific names carry their
// edition into Finding.Edition, so a known edition only sees its own
// findings plus the unrestricted one.
func TestLoadBDUEditionFromProductName(t *testing.T) {
	idx, err := LoadBDU(filepath.Join("testdata", "bdu_edition.xml"))
	if err != nil {
		t.Fatalf("LoadBDU: %v", err)
	}
	ids := func(edition string) map[string]bool {
		out := map[string]bool{}
		for _, f := range idx.Lookup("vault", "1.15.0", edition) {
			out[f.AdvisoryID] = true
		}
		return out
	}
	if got := ids("community"); len(got) != 2 || !got["BDU:2099-00020"] || !got["BDU:2099-00022"] {
		t.Fatalf("community got %v, want the unrestricted and the Community Edition entries", got)
	}
	if got := ids("enterprise"); len(got) != 2 || !got["BDU:2099-00020"] || !got["BDU:2099-00021"] {
		t.Fatalf("enterprise got %v, want the unrestricted and the Enterprise entries", got)
	}
	if got := ids(""); len(got) != 3 {
		t.Fatalf("unknown edition got %v, want all three", got)
	}
}
