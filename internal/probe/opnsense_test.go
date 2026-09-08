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

// opnsense_26.7.txt is a real `opnsense-version` reply captured over SSH
// from a live OPNsense 26.7 instance reached via vmactions/opnsense-vm (no
// Docker image or downloadable pre-installed image exists otherwise for an
// appliance OS like this).
func loadOPNsenseFixture(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "opnsense_26.7.txt"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return string(raw)
}

func TestOPNsenseProbeParsesRealFixture(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		"opnsense-version": loadOPNsenseFixture(t),
	})

	p := opnsenseProbe{}
	target := Target{
		ID: "x", Product: "opnsense", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	obs, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "26.7" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["hostKeyVerified"] != "true" {
		t.Fatalf("got Extra %+v, want hostKeyVerified=true", obs.Extra)
	}
}

func TestOPNsenseProbeCommandNotFoundIsErrNotSupported(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, nil) // no "opnsense-version" entry -> exit 1

	p := opnsenseProbe{}
	target := Target{
		ID: "x", Product: "opnsense", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	_, err := p.Probe(context.Background(), target)
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestOPNsenseProbeMeta(t *testing.T) {
	m := opnsenseProbe{}.Meta()
	if m.Product != "opnsense" {
		t.Fatalf("got product %q", m.Product)
	}
	if !m.Auth.Required {
		t.Fatal("ssh-based probes cannot work without credentials")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "opnsense" {
		t.Fatalf("got resolver %+v", m.DefaultResolver)
	}
}
