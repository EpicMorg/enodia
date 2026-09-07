// SPDX-License-Identifier: AGPL-3.0-or-later

package settings

import (
	"path/filepath"
	"testing"
)

func TestDefaultIsEmptyAndValid(t *testing.T) {
	s := Default()
	if err := s.Validate(); err != nil {
		t.Fatalf("Default() must already be valid: %v", err)
	}
	if s.Render.DefaultView != "" || s.HTML.Assets != "" || s.HTML.View != "" || s.HTML.Theme != "" {
		t.Fatalf("Default() should carry no overrides, got %+v", s)
	}
	if got := s.EffectiveTheme(); got != DefaultTheme {
		t.Fatalf("EffectiveTheme() = %q, want %q", got, DefaultTheme)
	}
}

func TestLoadParsesRealFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")
	writeFile(t, path, `
schemaVersion: 1
render:
  default_view: fleet
html:
  assets: cdn
  view: fleet
  theme: lumen
`)
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.Render.DefaultView != "fleet" {
		t.Errorf("got default_view %q, want fleet", s.Render.DefaultView)
	}
	if s.HTML.Assets != "cdn" || s.HTML.View != "fleet" || s.HTML.Theme != "lumen" {
		t.Errorf("got html %+v", s.HTML)
	}
	if got := s.EffectiveTheme(); got != "lumen" {
		t.Errorf("EffectiveTheme() = %q, want lumen", got)
	}
}

func TestLoadMissingSchemaVersionErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")
	writeFile(t, path, "render:\n  default_view: fleet\n")

	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for a missing schemaVersion")
	}
}

func TestLoadFutureSchemaVersionErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")
	writeFile(t, path, "schemaVersion: 99\n")

	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for a schemaVersion newer than this build understands")
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")
	writeFile(t, path, "schemaVersion: 1\ntypo_field: true\n")

	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an unknown top-level field")
	}
}

func TestLoadMissingFileErrors(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestResolveFallsBackToDefaultWhenNothingFound(t *testing.T) {
	if fileExists("/etc/enodia/settings.yaml") {
		t.Skip("this host actually has /etc/enodia/settings.yaml; the empty-search case can't be tested here")
	}

	clearSearchEnv(t)
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("HOME", t.TempDir())

	s, err := Resolve("")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if s.Render.DefaultView != "" {
		t.Fatalf("expected Default(), got %+v", s)
	}
}

func TestResolveLoadsExplicitPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")
	writeFile(t, path, "schemaVersion: 1\nrender:\n  default_view: drift\n")

	s, err := Resolve(path)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if s.Render.DefaultView != "drift" {
		t.Fatalf("got %+v", s)
	}
}

func TestResolvePropagatesExplicitPathError(t *testing.T) {
	if _, err := Resolve(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("expected an error for a missing explicit --settings path")
	}
}
