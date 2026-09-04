// SPDX-License-Identifier: AGPL-3.0-or-later

package settings

import (
	"os"
	"path/filepath"
	"testing"
)

func clearSearchEnv(t *testing.T) {
	t.Helper()
	t.Setenv("ENODIA_SETTINGS", "")
	t.Setenv("XDG_CONFIG_HOME", "")
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLocateExplicitPathMustExist(t *testing.T) {
	clearSearchEnv(t)
	dir := t.TempDir()

	if _, err := Locate(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("expected an error for a missing --settings path")
	}
}

func TestLocateExplicitPathFound(t *testing.T) {
	clearSearchEnv(t)
	dir := t.TempDir()
	want := filepath.Join(dir, "custom.yaml")
	writeFile(t, want, "schemaVersion: 1\n")

	got, err := Locate(want)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestLocateEnvVarMustExist(t *testing.T) {
	clearSearchEnv(t)
	dir := t.TempDir()
	t.Setenv("ENODIA_SETTINGS", filepath.Join(dir, "missing.yaml"))

	if _, err := Locate(""); err == nil {
		t.Fatal("expected an error for a missing $ENODIA_SETTINGS path")
	}
}

func TestLocateExplicitTakesPrecedenceOverEnvVar(t *testing.T) {
	clearSearchEnv(t)
	envPath := filepath.Join(t.TempDir(), "env.yaml")
	writeFile(t, envPath, "schemaVersion: 1\n")
	t.Setenv("ENODIA_SETTINGS", envPath)

	explicitPath := filepath.Join(t.TempDir(), "explicit.yaml")
	writeFile(t, explicitPath, "schemaVersion: 1\n")

	got, err := Locate(explicitPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != explicitPath {
		t.Fatalf("got %q, want %q (--settings should win over $ENODIA_SETTINGS)", got, explicitPath)
	}
}

func TestLocateFindsCwdSettingsYAML(t *testing.T) {
	clearSearchEnv(t)
	dir := t.TempDir()
	t.Chdir(dir)
	writeFile(t, filepath.Join(dir, "enodia.settings.yaml"), "schemaVersion: 1\n")

	got, err := Locate("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "enodia.settings.yaml" {
		t.Fatalf("got %q, want %q", got, "enodia.settings.yaml")
	}
}

func TestLocateFindsCwdDotfileWhenPlainOneAbsent(t *testing.T) {
	clearSearchEnv(t)
	dir := t.TempDir()
	t.Chdir(dir)
	writeFile(t, filepath.Join(dir, ".enodia.settings.yaml"), "schemaVersion: 1\n")

	got, err := Locate("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != ".enodia.settings.yaml" {
		t.Fatalf("got %q, want %q", got, ".enodia.settings.yaml")
	}
}

func TestLocateFindsCwdSettingsYML(t *testing.T) {
	clearSearchEnv(t)
	dir := t.TempDir()
	t.Chdir(dir)
	writeFile(t, filepath.Join(dir, "enodia.settings.yml"), "schemaVersion: 1\n")

	got, err := Locate("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "enodia.settings.yml" {
		t.Fatalf("got %q, want %q", got, "enodia.settings.yml")
	}
}

func TestLocateYAMLBeatsYMLAtSameLocation(t *testing.T) {
	clearSearchEnv(t)
	dir := t.TempDir()
	t.Chdir(dir)
	writeFile(t, filepath.Join(dir, "enodia.settings.yaml"), "schemaVersion: 1\n")
	writeFile(t, filepath.Join(dir, "enodia.settings.yml"), "schemaVersion: 1\n")

	got, err := Locate("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "enodia.settings.yaml" {
		t.Fatalf("got %q, want %q (.yaml should win over .yml at the same location)", got, "enodia.settings.yaml")
	}
}

func TestLocateFindsXDGConfigHome(t *testing.T) {
	clearSearchEnv(t)
	dir := t.TempDir()
	t.Chdir(dir) // empty: no ./enodia.settings.yaml or ./.enodia.settings.yaml here

	xdg := t.TempDir()
	want := filepath.Join(xdg, "enodia", "settings.yaml")
	writeFile(t, want, "schemaVersion: 1\n")
	t.Setenv("XDG_CONFIG_HOME", xdg)

	got, err := Locate("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestLocateCwdBeatsXDGConfigHome(t *testing.T) {
	clearSearchEnv(t)
	dir := t.TempDir()
	t.Chdir(dir)
	writeFile(t, filepath.Join(dir, "enodia.settings.yaml"), "schemaVersion: 1\n")

	xdg := t.TempDir()
	writeFile(t, filepath.Join(xdg, "enodia", "settings.yaml"), "schemaVersion: 1\n")
	t.Setenv("XDG_CONFIG_HOME", xdg)

	got, err := Locate("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "enodia.settings.yaml" {
		t.Fatalf("got %q, want %q", got, "enodia.settings.yaml")
	}
}

// Unlike config.Locate, finding nothing at all is not an error: settings
// are entirely optional (D19).
func TestLocateNothingFoundIsNotAnError(t *testing.T) {
	if fileExists("/etc/enodia/settings.yaml") {
		t.Skip("this host actually has /etc/enodia/settings.yaml; the empty-search case can't be tested here")
	}

	clearSearchEnv(t)
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("HOME", t.TempDir())

	got, err := Locate("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("got %q, want empty (nothing found)", got)
	}
}
