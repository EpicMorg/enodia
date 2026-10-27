// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func withCVEUpdateFlags(t *testing.T, from, oval []string, dryRun bool) {
	t.Helper()
	prevFrom, prevOVAL, prevDry := cveUpdateFromFlag, cveUpdateOVALFlag, cveUpdateDryRunFlag
	cveUpdateFromFlag, cveUpdateOVALFlag, cveUpdateDryRunFlag = from, oval, dryRun
	t.Cleanup(func() { cveUpdateFromFlag, cveUpdateOVALFlag, cveUpdateDryRunFlag = prevFrom, prevOVAL, prevDry })
}

func TestCVEUpdateDryRunPlansFromConfigAndInventory(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "enodia.yaml")
	writeFile(t, cfgPath, `schemaVersion: 1
targets: []
cve:
  bdu: {path: cve/vulxml.xml}
  oval: {path: cve/oval}
  nginx: {path: cve/nginx.html}
`)
	inv := filepath.Join(dir, "inventory.jsonl")
	writeFile(t, inv, `{"kind":"inventory","schemaVersion":1,"tool":"enodia test","collectedAt":"2026-10-09T00:00:00Z"}
{"kind":"observation","id":"h1","name":"h1","product":"rocky-linux","version":"9.4"}
`)
	withConfigFlag(t, cfgPath)
	withCVEUpdateFlags(t, []string{inv}, []string{"ubuntu:noble"}, true)

	cmd, stdout, stderr := testCmd(t)
	if err := runCVEUpdateCmd(cmd, nil); err != nil {
		t.Fatalf("runCVEUpdateCmd: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"rhel-9.oval.xml.bz2", "com.ubuntu.noble.usn.oval.xml.bz2", "security_advisories.html"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run lacks %s:\n%s", want, out)
		}
	}
	// cve/vulxml.xml can't be fetched as is: a warning, not a planned item.
	if !strings.Contains(stderr.String(), "cve.bdu.path") || strings.Contains(out, "bdu.fstec.ru") {
		t.Errorf("want a cve.bdu.path warning and no BDU item; stdout:\n%s\nstderr:\n%s", out, stderr)
	}
}

func TestCVEUpdateNeedsAPath(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "enodia.yaml")
	writeFile(t, cfgPath, "schemaVersion: 1\ntargets: []\n")
	withConfigFlag(t, cfgPath)
	withCVEUpdateFlags(t, nil, nil, false)

	cmd, _, _ := testCmd(t)
	var ee *ExitError
	if err := runCVEUpdateCmd(cmd, nil); !errors.As(err, &ee) || ee.Code != 2 {
		t.Fatalf("got %v, want exit 2", err)
	}
}

func TestCVEUpdateBadCAFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "enodia.yaml")
	writeFile(t, filepath.Join(dir, "not-a-cert.pem"), "hello")
	writeFile(t, cfgPath, `schemaVersion: 1
targets: []
cve:
  nginx: {path: nginx.html}
  update: {ca_file: not-a-cert.pem}
`)
	withConfigFlag(t, cfgPath)
	withCVEUpdateFlags(t, nil, nil, false)

	cmd, _, _ := testCmd(t)
	if err := runCVEUpdateCmd(cmd, nil); err == nil || !strings.Contains(err.Error(), "ca_file") {
		t.Fatalf("got %v, want a ca_file error", err)
	}
}

func TestCVEUpdateNothingToFetchForAlpine(t *testing.T) {
	// No Alpine host known: an empty cve/alpine would make check refuse the
	// config, so cve update says so instead of succeeding quietly.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "enodia.yaml")
	writeFile(t, cfgPath, `schemaVersion: 1
targets: []
cve:
  alpine: {path: cve/alpine}
`)
	withConfigFlag(t, cfgPath)
	withCVEUpdateFlags(t, nil, nil, false)

	cmd, _, stderr := testCmd(t)
	var ee *ExitError
	if err := runCVEUpdateCmd(cmd, nil); !errors.As(err, &ee) || ee.Code != 1 {
		t.Fatalf("got %v, want exit 1", err)
	}
	if !strings.Contains(stderr.String(), "no Alpine branch to fetch") {
		t.Errorf("stderr lacks the reason:\n%s", stderr)
	}
}
