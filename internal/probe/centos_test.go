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

func loadCentOSFixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return string(raw)
}

// centos_5.11.txt, centos_6.10.txt and centos_7.9.2009.txt are real
// /etc/redhat-release captures from centos:5, :6 and :7 — confirmed live
// that CentOS 5 and 6 predate the os-release convention entirely.
func TestCentOSProbeParsesRealFixtures(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		version string
	}{
		{"centos_5.11.txt", "5.11"},
		{"centos_6.10.txt", "6.10"},
		{"centos_7.9.2009.txt", "7.9.2009"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
				"cat /etc/redhat-release": loadCentOSFixture(t, tc.fixture),
			})

			p := centosProbe{}
			target := Target{
				ID: "x", Product: "centos", Address: addr,
				Creds:   Credentials{Username: "probeuser", Password: "probepass"},
				TLS:     TLSSettings{PinSHA256: []string{fp}},
				Timeout: 2 * time.Second,
			}

			obs, err := p.Probe(context.Background(), target)
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if obs.Version != tc.version {
				t.Fatalf("got version %q, want %q", obs.Version, tc.version)
			}
			if obs.Extra["hostKeyVerified"] != "true" {
				t.Fatalf("got Extra %+v, want hostKeyVerified=true", obs.Extra)
			}
		})
	}
}

// A real CentOS Stream 9's /etc/redhat-release ("CentOS Stream release 9")
// must not be misidentified as product: centos.
func TestCentOSProbeRejectsCentOSStream(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		"cat /etc/redhat-release": "CentOS Stream release 9\n",
	})

	p := centosProbe{}
	target := Target{
		ID: "x", Product: "centos", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	_, err := p.Probe(context.Background(), target)
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestCentOSProbeMissingFileIsErrNotSupported(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, nil) // no "cat /etc/redhat-release" entry -> exit 1

	p := centosProbe{}
	target := Target{
		ID: "x", Product: "centos", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	_, err := p.Probe(context.Background(), target)
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestCentOSProbeMeta(t *testing.T) {
	m := centosProbe{}.Meta()
	if m.Product != "centos" {
		t.Fatalf("got product %q", m.Product)
	}
	if !m.Auth.Required {
		t.Fatal("ssh-based probes cannot work without credentials")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "centos" {
		t.Fatalf("got resolver %+v", m.DefaultResolver)
	}
}
