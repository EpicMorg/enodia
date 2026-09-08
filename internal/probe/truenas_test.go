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

// truenas_25.10.7.txt is a real /etc/version capture: "25.10.7", from the
// user's own TrueNAS install.
func loadTrueNASFixture(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "truenas_25.10.7.txt"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return string(raw)
}

func TestTrueNASProbeParsesRealFixture(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		"cat /etc/version": loadTrueNASFixture(t),
	})

	p := truenasProbe{}
	target := Target{
		ID: "x", Product: "truenas", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	obs, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "25.10.7" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["hostKeyVerified"] != "true" {
		t.Fatalf("got Extra %+v, want hostKeyVerified=true", obs.Extra)
	}
}

func TestTrueNASProbeMissingFileIsErrNotSupported(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, nil) // no "cat /etc/version" entry -> exit 1

	p := truenasProbe{}
	target := Target{
		ID: "x", Product: "truenas", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	_, err := p.Probe(context.Background(), target)
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestTrueNASProbeGarbageContentIsErrUnparseable(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		"cat /etc/version": "not-a-version\n",
	})

	p := truenasProbe{}
	target := Target{
		ID: "x", Product: "truenas", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	_, err := p.Probe(context.Background(), target)
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestTrueNASProbeMeta(t *testing.T) {
	m := truenasProbe{}.Meta()
	if m.Product != "truenas" {
		t.Fatalf("got product %q", m.Product)
	}
	if !m.Auth.Required {
		t.Fatal("ssh-based probes cannot work without credentials")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "truenas" {
		t.Fatalf("got resolver %+v", m.DefaultResolver)
	}
}
