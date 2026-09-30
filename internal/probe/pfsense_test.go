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

func loadPfsenseFixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return string(raw)
}

const pfsenseProbeCmd = "cat /etc/version; echo '" + pfsenseVersionMarker + "'; cat /etc/platform"

func pfsenseTestTarget(addr, fp string) Target {
	return Target{
		ID: "x", Product: "pfsense", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}
}

// pfsense_2.8.1.txt is real: /etc/version + /etc/platform captured live,
// combined via cat+marker+cat, from a real pfSense CE 2.8.1 host.
func TestPfsenseProbeParsesRealFixture(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		pfsenseProbeCmd: loadPfsenseFixture(t, "pfsense_2.8.1.txt"),
	})

	p := pfsenseProbe{}
	obs, err := p.Probe(context.Background(), pfsenseTestTarget(addr, fp))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "2.8.1-RELEASE" {
		t.Fatalf("got version %q, want 2.8.1-RELEASE", obs.Version)
	}
	if obs.Extra["hostKeyVerified"] != "true" {
		t.Fatalf("got Extra %+v, want hostKeyVerified=true", obs.Extra)
	}
}

// pfSense Plus is a different Netgate product with its own calendar-based
// version scheme; no live Plus instance was available to confirm its exact
// /etc/platform string, so this uses the documented value ("pfSense-Plus")
// rather than one confirmed live — see pfsense.go's own doc comment.
func TestPfsenseProbeRejectsPfSensePlus(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		pfsenseProbeCmd: "24.11\n" + pfsenseVersionMarker + "\npfSense-Plus\n",
	})

	p := pfsenseProbe{}
	_, err := p.Probe(context.Background(), pfsenseTestTarget(addr, fp))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestPfsenseProbeRejectsUnknownPlatform(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		pfsenseProbeCmd: "2.8.1-RELEASE\n" + pfsenseVersionMarker + "\nOPNsense\n",
	})

	p := pfsenseProbe{}
	_, err := p.Probe(context.Background(), pfsenseTestTarget(addr, fp))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestPfsenseProbeMissingFileIsErrNotSupported(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, nil) // no matching command -> exit 1

	p := pfsenseProbe{}
	_, err := p.Probe(context.Background(), pfsenseTestTarget(addr, fp))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestPfsenseProbeMeta(t *testing.T) {
	m := pfsenseProbe{}.Meta()
	if m.Product != "pfsense" {
		t.Fatalf("got product %q", m.Product)
	}
	if !m.Auth.Required {
		t.Fatal("ssh-based probes cannot work without credentials")
	}
	if m.DefaultResolver.Type != "" {
		t.Fatalf("got resolver %+v, want none (no endoflife.date page for pfSense, confirmed 404)", m.DefaultResolver)
	}
}
