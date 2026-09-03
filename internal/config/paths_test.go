// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// clearSearchEnv keeps the search purely a function of the given filesystem
// state, uncontaminated by whatever the host running the tests happens to
// have set.
func clearSearchEnv(t *testing.T) {
	t.Helper()
	t.Setenv("ENODIA_CONFIG", "")
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
		t.Fatal("expected an error for a missing --config path")
	}
}

func TestLocateExplicitPathNeverFallsBack(t *testing.T) {
	clearSearchEnv(t)
	dir := t.TempDir()
	t.Chdir(dir)

	// A config exists in the working directory, but the explicit path is
	// still wrong and must still be an error, not a silent switch to it.
	writeFile(t, filepath.Join(dir, "enodia.yaml"), "schemaVersion: 1\n")

	_, err := Locate(filepath.Join(dir, "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("explicit --config path fell back instead of erroring")
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
	t.Setenv("ENODIA_CONFIG", filepath.Join(dir, "missing.yaml"))

	if _, err := Locate(""); err == nil {
		t.Fatal("expected an error for a missing $ENODIA_CONFIG path")
	}
}

func TestLocateEnvVarTakesPrecedenceOverCwd(t *testing.T) {
	clearSearchEnv(t)
	dir := t.TempDir()
	t.Chdir(dir)
	writeFile(t, filepath.Join(dir, "enodia.yaml"), "schemaVersion: 1\n# cwd\n")

	envPath := filepath.Join(t.TempDir(), "env.yaml")
	writeFile(t, envPath, "schemaVersion: 1\n# env\n")
	t.Setenv("ENODIA_CONFIG", envPath)

	got, err := Locate("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != envPath {
		t.Fatalf("got %q, want %q (env var should win over ./enodia.yaml)", got, envPath)
	}
}

func TestLocateExplicitTakesPrecedenceOverEnvVar(t *testing.T) {
	clearSearchEnv(t)
	envPath := filepath.Join(t.TempDir(), "env.yaml")
	writeFile(t, envPath, "schemaVersion: 1\n")
	t.Setenv("ENODIA_CONFIG", envPath)

	explicitPath := filepath.Join(t.TempDir(), "explicit.yaml")
	writeFile(t, explicitPath, "schemaVersion: 1\n")

	got, err := Locate(explicitPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != explicitPath {
		t.Fatalf("got %q, want %q (--config should win over $ENODIA_CONFIG)", got, explicitPath)
	}
}

func TestLocateFindsCwdEnodiaYAML(t *testing.T) {
	clearSearchEnv(t)
	dir := t.TempDir()
	t.Chdir(dir)
	writeFile(t, filepath.Join(dir, "enodia.yaml"), "schemaVersion: 1\n")

	got, err := Locate("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "enodia.yaml" {
		t.Fatalf("got %q, want %q", got, "enodia.yaml")
	}
}

func TestLocateFindsCwdDotEnodiaYAMLWhenPlainOneAbsent(t *testing.T) {
	clearSearchEnv(t)
	dir := t.TempDir()
	t.Chdir(dir)
	writeFile(t, filepath.Join(dir, ".enodia.yaml"), "schemaVersion: 1\n")

	got, err := Locate("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != ".enodia.yaml" {
		t.Fatalf("got %q, want %q", got, ".enodia.yaml")
	}
}

func TestLocatePlainEnodiaYAMLBeatsDotfile(t *testing.T) {
	clearSearchEnv(t)
	dir := t.TempDir()
	t.Chdir(dir)
	writeFile(t, filepath.Join(dir, "enodia.yaml"), "schemaVersion: 1\n")
	writeFile(t, filepath.Join(dir, ".enodia.yaml"), "schemaVersion: 1\n")

	got, err := Locate("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "enodia.yaml" {
		t.Fatalf("got %q, want %q", got, "enodia.yaml")
	}
}

func TestLocateFindsXDGConfigHome(t *testing.T) {
	clearSearchEnv(t)
	dir := t.TempDir()
	t.Chdir(dir) // empty: no ./enodia.yaml or ./.enodia.yaml here

	xdg := t.TempDir()
	want := filepath.Join(xdg, "enodia", "enodia.yaml")
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
	writeFile(t, filepath.Join(dir, "enodia.yaml"), "schemaVersion: 1\n")

	xdg := t.TempDir()
	writeFile(t, filepath.Join(xdg, "enodia", "enodia.yaml"), "schemaVersion: 1\n")
	t.Setenv("XDG_CONFIG_HOME", xdg)

	got, err := Locate("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "enodia.yaml" {
		t.Fatalf("got %q, want %q", got, "enodia.yaml")
	}
}

func TestLocateFallsBackToHomeConfigWhenXDGUnset(t *testing.T) {
	clearSearchEnv(t)
	dir := t.TempDir()
	t.Chdir(dir)

	home := t.TempDir()
	want := filepath.Join(home, ".config", "enodia", "enodia.yaml")
	writeFile(t, want, "schemaVersion: 1\n")
	t.Setenv("HOME", home)

	got, err := Locate("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestLocateNothingFoundIsErrNotFound(t *testing.T) {
	if fileExists("/etc/enodia/enodia.yaml") {
		t.Skip("this host actually has /etc/enodia/enodia.yaml; the empty-search case can't be tested here")
	}

	clearSearchEnv(t)
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("HOME", t.TempDir())

	_, err := Locate("")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("got error %v, want ErrNotFound", err)
	}
}
