// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/http"
	"net/http/httptest"
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
