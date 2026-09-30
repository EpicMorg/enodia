// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunConfigPathCmd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enodia.yaml")
	writeFile(t, path, "schemaVersion: 1\n")
	withConfigFlag(t, path)

	cmd, stdout, _ := testCmd(t)
	if err := runConfigPathCmd(cmd, nil); err != nil {
		t.Fatalf("runConfigPathCmd: %v", err)
	}
	if got := strings.TrimSpace(stdout.String()); got != path {
		t.Fatalf("got %q, want %q", got, path)
	}
}

func TestRunConfigPathCmdMissingIsError(t *testing.T) {
	withConfigFlag(t, filepath.Join(t.TempDir(), "nope.yaml"))
	cmd, _, _ := testCmd(t)
	if err := runConfigPathCmd(cmd, nil); err == nil {
		t.Fatal("expected an error")
	}
}

func TestRunConfigValidateCmdOK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enodia.yaml")
	writeFile(t, path, `
schemaVersion: 1
targets:
  - id: a
    product: generic
    address: https://a.example.com
`)
	withConfigFlag(t, path)

	cmd, stdout, _ := testCmd(t)
	if err := runConfigValidateCmd(cmd, nil); err != nil {
		t.Fatalf("runConfigValidateCmd: %v", err)
	}
	if !strings.Contains(stdout.String(), "OK") {
		t.Fatalf("got %q", stdout.String())
	}
}

func TestRunConfigValidateCmdBadCredentialReference(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enodia.yaml")
	writeFile(t, path, `
schemaVersion: 1
targets:
  - id: a
    product: generic
    address: https://a.example.com
    credentials: does-not-exist
`)
	withConfigFlag(t, path)

	cmd, _, _ := testCmd(t)
	if err := runConfigValidateCmd(cmd, nil); err == nil {
		t.Fatal("expected an error for an unresolvable credential reference")
	}
}

// The reported bug: a typo'd or moved cve.bdu.path/cve.nvd.path passed
// `config validate` clean and only surfaced as a failure deep inside
// `check`/`serve` (loadCVEIndex). credentials_file already gets an
// equivalent check for free from LoadCredentials' own os.ReadFile.
func TestRunConfigValidateCmdMissingBDUPathIsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enodia.yaml")
	writeFile(t, path, `
schemaVersion: 1
cve:
  bdu:
    path: does-not-exist.xml
targets:
  - id: a
    product: generic
    address: https://a.example.com
`)
	withConfigFlag(t, path)

	cmd, _, _ := testCmd(t)
	err := runConfigValidateCmd(cmd, nil)
	if err == nil {
		t.Fatal("expected an error for a nonexistent cve.bdu.path")
	}
	if !strings.Contains(err.Error(), "cve.bdu.path") {
		t.Fatalf("got %v, want it to name cve.bdu.path", err)
	}
}

func TestRunConfigValidateCmdMissingNVDPathIsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enodia.yaml")
	writeFile(t, path, `
schemaVersion: 1
cve:
  nvd:
    path: does-not-exist
targets:
  - id: a
    product: generic
    address: https://a.example.com
`)
	withConfigFlag(t, path)

	cmd, _, _ := testCmd(t)
	err := runConfigValidateCmd(cmd, nil)
	if err == nil {
		t.Fatal("expected an error for a nonexistent cve.nvd.path")
	}
	if !strings.Contains(err.Error(), "cve.nvd.path") {
		t.Fatalf("got %v, want it to name cve.nvd.path", err)
	}
}

// A real BDU/NVD path (existence is all this checks for — not that it
// parses) must not block an otherwise-clean config.
func TestRunConfigValidateCmdRealCVEPathsOK(t *testing.T) {
	dir := t.TempDir()
	bduPath := filepath.Join(dir, "vulxml.xml")
	writeFile(t, bduPath, "<vulns/>")
	nvdDir := filepath.Join(dir, "nvd")
	if err := os.Mkdir(nvdDir, 0o755); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "enodia.yaml")
	writeFile(t, path, `
schemaVersion: 1
cve:
  bdu:
    path: vulxml.xml
  nvd:
    path: nvd
targets:
  - id: a
    product: generic
    address: https://a.example.com
`)
	withConfigFlag(t, path)

	cmd, stdout, _ := testCmd(t)
	if err := runConfigValidateCmd(cmd, nil); err != nil {
		t.Fatalf("runConfigValidateCmd: %v", err)
	}
	if !strings.Contains(stdout.String(), "OK") {
		t.Fatalf("got %q", stdout.String())
	}
}

func TestRunConfigResolveCmdReportsScheme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	dir := t.TempDir()
	path := filepath.Join(dir, "enodia.yaml")
	writeFile(t, path, `
schemaVersion: 1
targets:
  - id: no-scheme
    product: generic
    address: `+addr+`
    timeout: 2s
`)
	withConfigFlag(t, path)

	cmd, stdout, _ := testCmd(t)
	if err := runConfigResolveCmd(cmd, nil); err != nil {
		t.Fatalf("runConfigResolveCmd: %v", err)
	}
	if !strings.Contains(stdout.String(), "no-scheme: http") {
		t.Fatalf("got %q, want it to report the http scheme it found", stdout.String())
	}
}

func TestRunConfigResolveCmdSkipsExplicitScheme(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enodia.yaml")
	writeFile(t, path, `
schemaVersion: 1
targets:
  - id: has-scheme
    product: generic
    address: https://a.example.com
`)
	withConfigFlag(t, path)

	cmd, stdout, _ := testCmd(t)
	if err := runConfigResolveCmd(cmd, nil); err != nil {
		t.Fatalf("runConfigResolveCmd: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("a target with an explicit scheme must not be probed or reported, got %q", stdout.String())
	}
}
