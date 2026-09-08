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

func loadAstraFixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return string(raw)
}

// astra-linux_1.8.6.txt and astra-linux_1.7.9.txt are real /etc/astra_version
// captures from epicmorg/astralinux:1.8-main and :1.7-main.
func TestAstraLinuxProbeParsesRealFixtures(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		version string
	}{
		{"astra-linux_1.8.6.txt", "1.8.6"},
		{"astra-linux_1.7.9.txt", "1.7.9"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
				"cat /etc/astra_version": loadAstraFixture(t, tc.fixture),
			})

			p := astraLinuxProbe{}
			target := Target{
				ID: "x", Product: "astra-linux", Address: addr,
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

func TestAstraLinuxProbeMissingFileIsErrNotSupported(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, nil) // no "cat /etc/astra_version" entry -> exit 1

	p := astraLinuxProbe{}
	target := Target{
		ID: "x", Product: "astra-linux", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	_, err := p.Probe(context.Background(), target)
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestAstraLinuxProbeGarbageContentIsErrUnparseable(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		"cat /etc/astra_version": "not-a-version\n",
	})

	p := astraLinuxProbe{}
	target := Target{
		ID: "x", Product: "astra-linux", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	_, err := p.Probe(context.Background(), target)
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestAstraLinuxProbeMeta(t *testing.T) {
	m := astraLinuxProbe{}.Meta()
	if m.Product != "astra-linux" {
		t.Fatalf("got product %q", m.Product)
	}
	if !m.Auth.Required {
		t.Fatal("ssh-based probes cannot work without credentials")
	}
	if m.DefaultResolver.Type != "" {
		t.Fatalf("got resolver %+v, want none (endoflife.date has no Astra Linux calendar)", m.DefaultResolver)
	}
}
