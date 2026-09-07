// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCollectCmdWritesJSONLToStdout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(jiraManifest))
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "enodia.yaml")
	writeFile(t, path, `
schemaVersion: 1
targets:
  - id: jira-1
    product: jira
    address: `+srv.URL+`
    timeout: 5s
`)
	withConfigFlag(t, path)

	prevOut := collectOutputFlag
	collectOutputFlag = "-"
	t.Cleanup(func() { collectOutputFlag = prevOut })

	cmd, stdout, _ := testCmd(t)
	if err := runCollectCmd(cmd, nil); err != nil {
		t.Fatalf("runCollectCmd: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want a header and one observation:\n%s", len(lines), stdout.String())
	}
	var header struct{ Kind string }
	if err := json.Unmarshal([]byte(lines[0]), &header); err != nil || header.Kind != "inventory" {
		t.Fatalf("first line is not an inventory header: %s", lines[0])
	}
}

func TestRunCollectCmdWritesToFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(jiraManifest))
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "enodia.yaml")
	writeFile(t, cfgPath, `
schemaVersion: 1
targets:
  - id: jira-1
    product: jira
    address: `+srv.URL+`
    timeout: 5s
`)
	withConfigFlag(t, cfgPath)

	outPath := filepath.Join(dir, "inv.jsonl")
	prevOut := collectOutputFlag
	collectOutputFlag = outPath
	t.Cleanup(func() { collectOutputFlag = prevOut })

	cmd, stdout, _ := testCmd(t)
	if err := runCollectCmd(cmd, nil); err != nil {
		t.Fatalf("runCollectCmd: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected nothing on stdout when --output is a file, got %q", stdout.String())
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("output file was not created: %v", err)
	}
}

func TestRunCollectCmdBadConfigIsInternalError(t *testing.T) {
	withConfigFlag(t, filepath.Join(t.TempDir(), "nope.yaml"))
	cmd, _, _ := testCmd(t)
	err := runCollectCmd(cmd, nil)
	if err == nil {
		t.Fatal("expected an error for a missing config")
	}
}
