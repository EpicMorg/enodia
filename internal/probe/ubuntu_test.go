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

func loadUbuntuFixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return string(raw)
}

func ubuntuTestTarget(addr, fp string) Target {
	return Target{
		ID: "x", Product: "ubuntu", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}
}

// ubuntu_22.04.5.txt, ubuntu_24.04.txt and ubuntu_14.04.6.txt are real,
// live-captured os-release files (docker.io/ubuntu:22.04, :24.04, :14.04) —
// confirmed that VERSION_ID never changes after a release ships, even
// across several point releases; only VERSION (and PRETTY_NAME) carry the
// point release, in two different real shapes ("22.04.5 LTS (Jammy
// Jellyfish)" and the older "14.04.6 LTS, Trusty Tahr").
func TestUbuntuProbePrefersVersionFieldPointRelease(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		version string
	}{
		{"ubuntu_22.04.5.txt", "22.04.5"},
		{"ubuntu_24.04.txt", "24.04.4"},
		{"ubuntu_14.04.6.txt", "14.04.6"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
				"cat /etc/os-release": loadUbuntuFixture(t, tc.fixture),
			})

			p := ubuntuProbe{}
			obs, err := p.Probe(context.Background(), ubuntuTestTarget(addr, fp))
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if obs.Version != tc.version {
				t.Fatalf("got version %q, want %q", obs.Version, tc.version)
			}
		})
	}
}

// A non-LTS release only ever ships once — its VERSION carries no extra
// segment beyond VERSION_ID at all (confirmed live: ubuntu:24.10 reports
// VERSION="24.10 (Oracular Oriole)", identical precision to VERSION_ID).
func TestUbuntuProbeNonLTSHasNoExtraPrecisionToPrefer(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		"cat /etc/os-release": loadUbuntuFixture(t, "ubuntu_24.10.txt"),
	})

	p := ubuntuProbe{}
	obs, err := p.Probe(context.Background(), ubuntuTestTarget(addr, fp))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "24.10" {
		t.Fatalf("got version %q, want 24.10", obs.Version)
	}
}

func TestUbuntuProbeRejectsNonUbuntu(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		"cat /etc/os-release": "ID=debian\nVERSION_ID=\"13\"\n",
	})

	p := ubuntuProbe{}
	_, err := p.Probe(context.Background(), ubuntuTestTarget(addr, fp))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestUbuntuProbeMissingFileIsErrNotSupported(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, nil) // no "cat /etc/os-release" entry -> exit 1

	p := ubuntuProbe{}
	_, err := p.Probe(context.Background(), ubuntuTestTarget(addr, fp))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestUbuntuProbeMeta(t *testing.T) {
	m := ubuntuProbe{}.Meta()
	if m.Product != "ubuntu" {
		t.Fatalf("got product %q", m.Product)
	}
	if !m.Auth.Required {
		t.Fatal("ssh-based probes cannot work without credentials")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "ubuntu" {
		t.Fatalf("got resolver %+v", m.DefaultResolver)
	}
}
