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

func loadUnameFixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return string(raw)
}

// openbsd_7.9.txt and netbsd_11.0.txt are real `uname -sr` replies captured
// from live systems via vmactions' GitHub Actions (openbsd-vm, netbsd-vm) —
// no Docker image or downloadable pre-installed VM image exists for either
// (see DECISIONS.md D23).
func TestUnameFamilyRealFixtures(t *testing.T) {
	cases := map[string]struct {
		fixture string
		probe   unameFamilyProbe
		version string
	}{
		"openbsd": {"openbsd_7.9.txt", unameFamilyProbe{product: "openbsd", unameName: "OpenBSD"}, "7.9"},
		"netbsd":  {"netbsd_11.0.txt", unameFamilyProbe{product: "netbsd", unameName: "NetBSD"}, "11.0"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := loadUnameFixture(t, tc.fixture)
			addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
				"uname -sr": fixture,
			})

			target := Target{
				ID: "x", Product: tc.probe.product, Address: addr,
				Creds:   Credentials{Username: "probeuser", Password: "probepass"},
				TLS:     TLSSettings{PinSHA256: []string{fp}},
				Timeout: 2 * time.Second,
			}

			obs, err := tc.probe.Probe(context.Background(), target)
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

// The whole point of D9: an OpenBSD box under product: netbsd fails loudly.
func TestUnameFamilyWrongProductIsErrNotSupported(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		"uname -sr": loadUnameFixture(t, "openbsd_7.9.txt"),
	})

	netbsd := unameFamilyProbe{product: "netbsd", unameName: "NetBSD"}
	target := Target{
		ID: "x", Product: "netbsd", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	_, err := netbsd.Probe(context.Background(), target)
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestUnameFamilyCommandFailureIsErrNotSupported(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, nil) // no "uname -sr" entry -> exit 1

	openbsd := unameFamilyProbe{product: "openbsd", unameName: "OpenBSD"}
	target := Target{
		ID: "x", Product: "openbsd", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	_, err := openbsd.Probe(context.Background(), target)
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestUnameFamilyMeta(t *testing.T) {
	m := unameFamilyProbe{product: "openbsd", summary: "OpenBSD", resolver: ResolverRef{Type: "endoflife", ID: "openbsd"}}.Meta()
	if m.Product != "openbsd" {
		t.Fatalf("got product %q", m.Product)
	}
	if !m.Auth.Required {
		t.Fatal("ssh-based probes cannot work without credentials")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "openbsd" {
		t.Fatalf("got resolver %+v", m.DefaultResolver)
	}
	if m.DefaultScheme != "" {
		t.Fatalf("got DefaultScheme %q, want empty (SSH has no URL scheme, D10)", m.DefaultScheme)
	}
}
