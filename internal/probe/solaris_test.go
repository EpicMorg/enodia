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

// oracle-solaris_11.4.txt is a real /etc/release capture from a live Oracle
// Solaris 11.4 instance, reached via vmactions/solaris-vm — no downloadable
// image is obtainable without an Oracle account (see DECISIONS.md D23);
// vmactions builds and republishes Oracle's own free-to-redistribute
// Solaris CBE.
func loadSolarisFixture(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "oracle-solaris_11.4.txt"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return string(raw)
}

func TestOracleSolarisProbeParsesRealFixture(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		"cat /etc/release": loadSolarisFixture(t),
	})

	p := oracleSolarisProbe{}
	target := Target{
		ID: "x", Product: "oracle-solaris", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	obs, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "11.4" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["hostKeyVerified"] != "true" {
		t.Fatalf("got Extra %+v, want hostKeyVerified=true", obs.Extra)
	}
}

func TestOracleSolarisProbeMissingFileIsErrNotSupported(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, nil) // no "cat /etc/release" entry -> exit 1

	p := oracleSolarisProbe{}
	target := Target{
		ID: "x", Product: "oracle-solaris", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	_, err := p.Probe(context.Background(), target)
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestOracleSolarisProbeWrongContentIsErrNotSupported(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		"cat /etc/release": "                       OmniOS v11 r151048\n",
	})

	p := oracleSolarisProbe{}
	target := Target{
		ID: "x", Product: "oracle-solaris", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	_, err := p.Probe(context.Background(), target)
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestOracleSolarisProbeMeta(t *testing.T) {
	m := oracleSolarisProbe{}.Meta()
	if m.Product != "oracle-solaris" {
		t.Fatalf("got product %q", m.Product)
	}
	if !m.Auth.Required {
		t.Fatal("ssh-based probes cannot work without credentials")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "oracle-solaris" {
		t.Fatalf("got resolver %+v", m.DefaultResolver)
	}
}
