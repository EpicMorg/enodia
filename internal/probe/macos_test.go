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

// macos_15.4.txt is a real `sw_vers` reply captured over SSH from a live
// Mac (macOS 15.4, BuildVersion 24E248). sw_vers carries no hostname —
// unlike `uname -a` on Darwin — so nothing needed scrubbing here.
func loadMacOSFixture(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "macos_15.4.txt"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return string(raw)
}

func TestMacOSProbeParsesRealFixture(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		"sw_vers": loadMacOSFixture(t),
	})

	p := macosProbe{}
	target := Target{
		ID: "x", Product: "macos", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	obs, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "15.4" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["buildVersion"] != "24E248" {
		t.Fatalf("got Extra %+v", obs.Extra)
	}
	if obs.Extra["hostKeyVerified"] != "true" {
		t.Fatalf("got Extra %+v, want hostKeyVerified=true", obs.Extra)
	}
}

func TestMacOSProbeWrongProductIsErrNotSupported(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		"sw_vers": "ProductName:\t\tMac OS X\nProductVersion:\t\t10.11\nBuildVersion:\t\t15G31\n",
	})

	p := macosProbe{}
	target := Target{
		ID: "x", Product: "macos", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	_, err := p.Probe(context.Background(), target)
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestMacOSProbeCommandNotFoundIsErrNotSupported(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, nil) // no "sw_vers" entry -> exit 1

	p := macosProbe{}
	target := Target{
		ID: "x", Product: "macos", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	_, err := p.Probe(context.Background(), target)
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestMacOSProbeMeta(t *testing.T) {
	m := macosProbe{}.Meta()
	if m.Product != "macos" {
		t.Fatalf("got product %q", m.Product)
	}
	if !m.Auth.Required {
		t.Fatal("ssh-based probes cannot work without credentials")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "macos" {
		t.Fatalf("got resolver %+v", m.DefaultResolver)
	}
	if m.DefaultScheme != "" {
		t.Fatalf("got DefaultScheme %q, want empty (SSH has no URL scheme, D10)", m.DefaultScheme)
	}
}

func TestParseSwVers(t *testing.T) {
	fields := parseSwVers("ProductName:\t\tmacOS\nProductVersion:\t\t15.4\nBuildVersion:\t\t24E248\n")
	if fields["ProductName"] != "macOS" || fields["ProductVersion"] != "15.4" || fields["BuildVersion"] != "24E248" {
		t.Fatalf("got %+v", fields)
	}
}
