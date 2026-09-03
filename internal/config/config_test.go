// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestLoadMissingSchemaVersionErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enodia.yaml")
	writeFile(t, path, `
targets:
  - id: jira
    product: jira
    address: https://jira.example.com
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for a missing schemaVersion")
	}
}

func TestLoadFutureSchemaVersionErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enodia.yaml")
	writeFile(t, path, "schemaVersion: 999\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for a schemaVersion newer than this build supports")
	}
}

func TestLoadDuplicateTargetIDErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enodia.yaml")
	writeFile(t, path, `
schemaVersion: 1
targets:
  - id: dup
    product: jira
    address: https://a.example.com
  - id: dup
    product: jira
    address: https://b.example.com
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for duplicate target ids")
	}
}

func TestLoadTargetMissingRequiredFieldsErrors(t *testing.T) {
	cases := []string{
		"schemaVersion: 1\ntargets:\n  - product: jira\n    address: https://a.example.com\n",
		"schemaVersion: 1\ntargets:\n  - id: a\n    address: https://a.example.com\n",
		"schemaVersion: 1\ntargets:\n  - id: a\n    product: jira\n",
	}
	for i, content := range cases {
		dir := t.TempDir()
		path := filepath.Join(dir, "enodia.yaml")
		writeFile(t, path, content)
		if _, err := Load(path); err == nil {
			t.Fatalf("case %d: expected an error", i)
		}
	}
}

func TestLoadUnknownFieldErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enodia.yaml")
	writeFile(t, path, `
schemaVersion: 1
this_is_not_a_real_field: true
targets: []
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an unknown top-level field (typo protection)")
	}
}

func TestLoadValidMinimalConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enodia.yaml")
	writeFile(t, path, `
schemaVersion: 1
targets:
  - id: jira
    product: jira
    address: https://jira.example.com
`)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.Targets) != 1 || c.Targets[0].ID != "jira" {
		t.Fatalf("got %+v", c.Targets)
	}
}

func TestLoadInterpolatesBeforeParsing(t *testing.T) {
	t.Setenv("ENODIA_TEST_ADDRESS", "jira.example.com")
	dir := t.TempDir()
	path := filepath.Join(dir, "enodia.yaml")
	writeFile(t, path, `
schemaVersion: 1
targets:
  - id: jira
    product: jira
    address: https://${ENODIA_TEST_ADDRESS}
`)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := c.Targets[0].Address, "https://jira.example.com"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestLoadMissingConfigFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected an error for a missing config file")
	}
}

func TestBuildAppliesDefaultTimeout(t *testing.T) {
	dir := t.TempDir()
	c := loadConfig(t, dir, `
schemaVersion: 1
targets:
  - id: a
    product: generic
    address: https://a.example.com
`)
	targets, err := c.Build(nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if targets[0].Timeout != 10*time.Second {
		t.Fatalf("got %v, want 10s default", targets[0].Timeout)
	}
}

func TestBuildTargetTimeoutOverridesDefault(t *testing.T) {
	dir := t.TempDir()
	c := loadConfig(t, dir, `
schemaVersion: 1
defaults:
  timeout: 20s
targets:
  - id: a
    product: generic
    address: https://a.example.com
    timeout: 5s
`)
	targets, err := c.Build(nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if targets[0].Timeout != 5*time.Second {
		t.Fatalf("got %v, want 5s (target override)", targets[0].Timeout)
	}
}

func TestBuildDefaultsTimeoutAppliesAcrossTargets(t *testing.T) {
	dir := t.TempDir()
	c := loadConfig(t, dir, `
schemaVersion: 1
defaults:
  timeout: 20s
targets:
  - id: a
    product: generic
    address: https://a.example.com
`)
	targets, err := c.Build(nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if targets[0].Timeout != 20*time.Second {
		t.Fatalf("got %v, want 20s (defaults.timeout)", targets[0].Timeout)
	}
}

func TestBuildTargetNameDefaultsToID(t *testing.T) {
	dir := t.TempDir()
	c := loadConfig(t, dir, `
schemaVersion: 1
targets:
  - id: svc-a
    product: generic
    address: https://a.example.com
`)
	targets, err := c.Build(nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if targets[0].Name != "svc-a" {
		t.Fatalf("got %q, want %q", targets[0].Name, "svc-a")
	}
}

func TestBuildInvalidDurationErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enodia.yaml")
	writeFile(t, path, `
schemaVersion: 1
targets:
  - id: a
    product: generic
    address: https://a.example.com
    timeout: not-a-duration
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an invalid duration")
	}
}
