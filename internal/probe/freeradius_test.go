// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func freeradiusTarget(addr, fp string, options map[string]string) Target {
	return Target{
		ID: "x", Product: "freeradius", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
		Options: options,
	}
}

func loadFreeradiusFixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// freeradius_3.2.10.txt is the command's real output from a FreeRADIUS
// 3.2.10 running in Docker (container "freeradius");
// freeradius_not_installed.txt is the same command's output on that
// container's host, which has no FreeRADIUS binary of its own.
func TestFreeradiusProbeInContainer(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		"docker exec freeradius sh -c '" + freeradiusVersionCommand + "'": loadFreeradiusFixture(t, "freeradius_3.2.10.txt"),
	})
	obs, err := freeradiusProbe{}.Probe(context.Background(), freeradiusTarget(addr, fp, map[string]string{"container": "freeradius"}))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "3.2.10" || obs.Extra["git"] != "9071ea041" || obs.Extra["container"] != "freeradius" || obs.Extra["hostKeyVerified"] != "true" {
		t.Fatalf("got version %q, Extra %v", obs.Version, obs.Extra)
	}
}

func TestFreeradiusProbeOnHost(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		freeradiusVersionCommand: loadFreeradiusFixture(t, "freeradius_3.2.10.txt"),
	})
	obs, err := freeradiusProbe{}.Probe(context.Background(), freeradiusTarget(addr, fp, nil))
	if err != nil || obs.Version != "3.2.10" {
		t.Fatalf("got %q, %v", obs.Version, err)
	}
}

func TestFreeradiusProbeNotInstalledIsErrNotSupported(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		freeradiusVersionCommand: loadFreeradiusFixture(t, "freeradius_not_installed.txt"),
	})
	_, err := freeradiusProbe{}.Probe(context.Background(), freeradiusTarget(addr, fp, nil))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

// docker exec itself failing (no such container) is the one way the
// command can still exit nonzero.
func TestFreeradiusProbeMissingContainerIsErrNotSupported(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, nil)
	_, err := freeradiusProbe{}.Probe(context.Background(), freeradiusTarget(addr, fp, map[string]string{"container": "nope"}))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestContainerCommandOptions(t *testing.T) {
	cmd, err := containerCommand(Target{Options: map[string]string{"container": "radius-1", "container_runtime": "podman"}}, freeradiusVersionCommand)
	if err != nil || cmd != "podman exec radius-1 sh -c '"+freeradiusVersionCommand+"'" {
		t.Fatalf("got %q, %v", cmd, err)
	}
	for _, opts := range []map[string]string{
		{"container": "x; rm -rf /"},
		{"container": "x", "container_runtime": "nerdctl"},
	} {
		if _, err := containerCommand(Target{Options: opts}, freeradiusVersionCommand); !errors.Is(err, ErrNotSupported) {
			t.Errorf("%v: got %v, want ErrNotSupported", opts, err)
		}
	}
}

func TestFreeradiusProbeMeta(t *testing.T) {
	m := freeradiusProbe{}.Meta()
	if m.Product != "freeradius" || !m.Auth.Required || m.DefaultResolver.Type != "github-tag-branches" {
		t.Fatalf("got %+v", m)
	}
}
