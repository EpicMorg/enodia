// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

func TestBDUPathUnset(t *testing.T) {
	dir := t.TempDir()
	c := loadConfig(t, dir, `
schemaVersion: 1
targets: []
`)
	if _, ok := c.BDUPath(); ok {
		t.Fatal("expected ok=false when cve.bdu.path was never set")
	}
}

func TestBDUPathRelativeToConfigDir(t *testing.T) {
	dir := t.TempDir()
	c := loadConfig(t, dir, `
schemaVersion: 1
cve:
  bdu:
    path: data/vulxml.zip
targets: []
`)
	path, ok := c.BDUPath()
	if !ok {
		t.Fatal("expected ok=true")
	}
	want := filepath.Join(dir, "data", "vulxml.zip")
	if path != want {
		t.Fatalf("got %q, want %q", path, want)
	}
}

func TestBDUPathAbsoluteIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	abs := filepath.Join(dir, "somewhere-else", "vulxml.xml")
	c := loadConfig(t, dir, `
schemaVersion: 1
cve:
  bdu:
    path: `+abs+`
targets: []
`)
	path, ok := c.BDUPath()
	if !ok {
		t.Fatal("expected ok=true")
	}
	if path != abs {
		t.Fatalf("got %q, want %q (already absolute, must not be re-joined)", path, abs)
	}
}

func TestNVDPathUnset(t *testing.T) {
	dir := t.TempDir()
	c := loadConfig(t, dir, `
schemaVersion: 1
targets: []
`)
	if _, ok := c.NVDPath(); ok {
		t.Fatal("expected ok=false when cve.nvd.path was never set")
	}
}

func TestNVDPathRelativeToConfigDir(t *testing.T) {
	dir := t.TempDir()
	c := loadConfig(t, dir, `
schemaVersion: 1
cve:
  nvd:
    path: data/nvd
targets: []
`)
	path, ok := c.NVDPath()
	if !ok {
		t.Fatal("expected ok=true")
	}
	want := filepath.Join(dir, "data", "nvd")
	if path != want {
		t.Fatalf("got %q, want %q", path, want)
	}
}

// BDU and NVD paths are independent: setting one must not implicitly set
// or block the other, since an operator may configure either alone.
func TestBDUAndNVDPathsAreIndependent(t *testing.T) {
	dir := t.TempDir()
	c := loadConfig(t, dir, `
schemaVersion: 1
cve:
  bdu:
    path: data/vulxml.zip
targets: []
`)
	if _, ok := c.BDUPath(); !ok {
		t.Fatal("expected ok=true for cve.bdu.path")
	}
	if _, ok := c.NVDPath(); ok {
		t.Fatal("expected ok=false for cve.nvd.path, which was never set")
	}
}

// A Windows path written in YAML double quotes has its \t and \n turned
// into a tab and a newline by the YAML parser itself ("C:\temp\nvd").
// That must fail loudly at load, not later as a confusing "not found".
func TestCVEPathWithControlCharacterIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enodia.yaml")
	if err := os.WriteFile(path, []byte("schemaVersion: 1\ncve:\n  nvd:\n    path: \"C:\\temp\\nvd\"\ntargets: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "cve.nvd.path") || !strings.Contains(err.Error(), "single quotes") {
		t.Fatalf("got %v, want a cve.nvd.path control-character error with a fix hint", err)
	}
}

// Every other way to write a Windows path loads unchanged.
func TestCVEWindowsPathFormsLoad(t *testing.T) {
	for _, line := range []string{
		`path: C:\enodia\cve\nvd`,
		`path: 'C:\enodia\cve\nvd'`,
		`path: "C:\\enodia\\cve\\nvd"`,
		`path: C:/enodia/cve/nvd`,
		`path: \\fileserver\share\enodia\nvd`,
	} {
		path := filepath.Join(t.TempDir(), "enodia.yaml")
		if err := os.WriteFile(path, []byte("schemaVersion: 1\ncve:\n  nvd:\n    "+line+"\ntargets: []\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := Load(path)
		if err != nil {
			t.Errorf("%s: %v", line, err)
			continue
		}
		if strings.ContainsFunc(c.CVE.NVD.Path, unicode.IsControl) {
			t.Errorf("%s: got %q", line, c.CVE.NVD.Path)
		}
	}
}
