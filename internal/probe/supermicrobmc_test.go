// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func loadSupermicroBMCFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// supermicro-bmc_01.05.25.json (X12-series, AST2600) and
// _01.73.13.json (an older X9/X10-era board, plain "ASPEED") are real
// GET /redfish/v1/Managers/1 replies captured from two live Supermicro
// BMCs of different generations, with the UUID (MAC-address-derived)
// replaced by a fixed placeholder.
func TestSupermicroBMCProbeParsesRealFixtures(t *testing.T) {
	for _, tc := range []struct {
		fixture, version, model string
	}{
		{"supermicro-bmc_01.05.25.json", "01.05.25", "AST2600"},
		{"supermicro-bmc_01.73.13.json", "01.73.13", "ASPEED"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			fixture := loadSupermicroBMCFixture(t, tc.fixture)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/redfish/v1/Managers/1" {
					t.Errorf("got path %q, want /redfish/v1/Managers/1", r.URL.Path)
				}
				_, _ = w.Write(fixture)
			}))
			defer srv.Close()

			p := supermicroBMCProbe{}
			obs, err := p.Probe(context.Background(), target(srv.URL, "supermicro-bmc"))
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if obs.Version != tc.version {
				t.Fatalf("got version %q, want %q", obs.Version, tc.version)
			}
			if obs.Extra["model"] != tc.model {
				t.Fatalf("got Extra %+v, want model=%q", obs.Extra, tc.model)
			}
		})
	}
}

// A real Dell iDRAC's Manager resource carries no Oem key at all — must
// be rejected rather than silently parsed if a target is misdeclared.
func TestSupermicroBMCProbeRejectsNonSupermicro(t *testing.T) {
	fixture := loadDellIDRACFixture(t, "dell-idrac_2.65.65.65_manager.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := supermicroBMCProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "supermicro-bmc"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestSupermicroBMCProbeUnauthorizedIsErrAuth(t *testing.T) {
	// Confirmed live: a real Supermicro BMC answers 401 without
	// credentials on this exact resource.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := supermicroBMCProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "supermicro-bmc"))
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestSupermicroBMCProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := supermicroBMCProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "supermicro-bmc"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestSupermicroBMCProbeMeta(t *testing.T) {
	m := supermicroBMCProbe{}.Meta()
	if m.Product != "supermicro-bmc" {
		t.Fatalf("got product %q", m.Product)
	}
	if !m.Auth.Required {
		t.Fatal("a real Supermicro BMC needs credentials, confirmed live")
	}
	if m.DefaultResolver.Type != "" {
		t.Fatalf("got resolver %+v, want none (BMC firmware has no public lifecycle calendar)", m.DefaultResolver)
	}
}
