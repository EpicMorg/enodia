// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"path/filepath"
	"testing"
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
