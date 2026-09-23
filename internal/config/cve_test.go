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
