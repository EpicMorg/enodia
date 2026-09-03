// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/EpicMorg/enodia/internal/probe"
)

func loadConfig(t *testing.T, dir, content string) *Config {
	t.Helper()
	path := filepath.Join(dir, "enodia.yaml")
	writeFile(t, path, content)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

func TestCredentialsInlineOnlyIsUsed(t *testing.T) {
	dir := t.TempDir()
	c := loadConfig(t, dir, `
schemaVersion: 1
credentials:
  jira-token:
    kind: bearer
    value: inline-value
targets:
  - id: jira
    product: jira
    address: https://jira.example.com
    credentials: jira-token
`)

	store, err := c.LoadCredentials(nil)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if store["jira-token"].Value != "inline-value" {
		t.Fatalf("got %q, want %q", store["jira-token"].Value, "inline-value")
	}
}

func TestCredentialsFileWinsOverInlineSameName(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "credentials.yaml"), `
credentials:
  jira-token:
    kind: bearer
    value: from-file
`)
	c := loadConfig(t, dir, `
schemaVersion: 1
credentials_file: credentials.yaml
credentials:
  jira-token:
    kind: bearer
    value: from-inline
targets:
  - id: jira
    product: jira
    address: https://jira.example.com
    credentials: jira-token
`)

	store, err := c.LoadCredentials(nil)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if got, want := store["jira-token"].Value, "from-file"; got != want {
		t.Fatalf("got %q, want %q (credentials_file must win over inline)", got, want)
	}
}

func TestCredentialsFileAndInlineMerge(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "credentials.yaml"), `
credentials:
  file-only:
    kind: bearer
    value: from-file
`)
	c := loadConfig(t, dir, `
schemaVersion: 1
credentials_file: credentials.yaml
credentials:
  inline-only:
    kind: bearer
    value: from-inline
targets:
  - id: a
    product: jira
    address: https://a.example.com
    credentials: file-only
  - id: b
    product: jira
    address: https://b.example.com
    credentials: inline-only
`)

	store, err := c.LoadCredentials(nil)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if store["file-only"].Value != "from-file" {
		t.Fatalf("file-only credential missing or wrong: %+v", store["file-only"])
	}
	if store["inline-only"].Value != "from-inline" {
		t.Fatalf("inline-only credential missing or wrong: %+v", store["inline-only"])
	}
}

func TestCredentialsFileIsRelativeToConfigDir(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "creds")
	writeFile(t, filepath.Join(sub, "credentials.yaml"), `
credentials:
  jira-token:
    kind: bearer
    value: nested
`)
	c := loadConfig(t, dir, `
schemaVersion: 1
credentials_file: creds/credentials.yaml
targets:
  - id: jira
    product: jira
    address: https://jira.example.com
    credentials: jira-token
`)

	store, err := c.LoadCredentials(nil)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if store["jira-token"].Value != "nested" {
		t.Fatalf("got %+v", store["jira-token"])
	}
}

func TestCredentialsMissingReferenceErrors(t *testing.T) {
	dir := t.TempDir()
	c := loadConfig(t, dir, `
schemaVersion: 1
targets:
  - id: jira
    product: jira
    address: https://jira.example.com
    credentials: does-not-exist
`)

	_, err := c.Build(nil)
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("got %v, want ErrCredentialNotFound", err)
	}
}

func TestCredentialsResolveIntoProbeCredentials(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ENODIA_TEST_TOKEN", "secret-from-env")
	c := loadConfig(t, dir, `
schemaVersion: 1
credentials:
  jira-token:
    kind: bearer
    value: ${ENODIA_TEST_TOKEN}
targets:
  - id: jira
    product: jira
    address: https://jira.example.com
    credentials: jira-token
`)

	targets, err := c.Build(nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("got %d targets, want 1", len(targets))
	}
	got := targets[0].Creds
	if got.Kind != probe.AuthBearer || got.Value != "secret-from-env" {
		t.Fatalf("got %+v", got)
	}
}

func TestCredentialsNoReferenceIsZeroCredentials(t *testing.T) {
	dir := t.TempDir()
	c := loadConfig(t, dir, `
schemaVersion: 1
targets:
  - id: generic
    product: generic
    address: https://svc.example.com
`)

	targets, err := c.Build(nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !targets[0].Creds.IsZero() {
		t.Fatalf("expected zero credentials, got %+v", targets[0].Creds)
	}
}

func TestCredentialsFilePermissionWarning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on windows")
	}

	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.yaml")
	writeFile(t, credPath, "credentials:\n  jira-token:\n    kind: bearer\n    value: x\n")
	if err := os.Chmod(credPath, 0o644); err != nil {
		t.Fatal(err)
	}

	c := loadConfig(t, dir, `
schemaVersion: 1
credentials_file: credentials.yaml
targets:
  - id: jira
    product: jira
    address: https://jira.example.com
    credentials: jira-token
`)

	var warnings []string
	if _, err := c.LoadCredentials(func(msg string) { warnings = append(warnings, msg) }); err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if len(warnings) == 0 {
		t.Fatal("expected a permission warning for a 0644 credentials_file")
	}
}

func TestCredentialsFileStrictPermissionsNoWarning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on windows")
	}

	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.yaml")
	writeFile(t, credPath, "credentials:\n  jira-token:\n    kind: bearer\n    value: x\n")
	if err := os.Chmod(credPath, 0o600); err != nil {
		t.Fatal(err)
	}

	c := loadConfig(t, dir, `
schemaVersion: 1
credentials_file: credentials.yaml
targets:
  - id: jira
    product: jira
    address: https://jira.example.com
    credentials: jira-token
`)

	var warnings []string
	if _, err := c.LoadCredentials(func(msg string) { warnings = append(warnings, msg) }); err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings for a 0600 file: %v", warnings)
	}
}

func TestCredentialsUnknownKindErrors(t *testing.T) {
	dir := t.TempDir()
	c := loadConfig(t, dir, `
schemaVersion: 1
credentials:
  jira-token:
    kind: not-a-real-kind
    value: x
targets:
  - id: jira
    product: jira
    address: https://jira.example.com
    credentials: jira-token
`)

	if _, err := c.Build(nil); err == nil {
		t.Fatal("expected an error for an unknown credential kind")
	}
}
