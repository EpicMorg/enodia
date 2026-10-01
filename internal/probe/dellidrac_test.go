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

func loadDellIDRACFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// dellIDRACTestServer wires the two real fixtures (root + manager, both
// captured live from a real 12G Dell blade's iDRAC, with the service tag
// and MAC address scrubbed) to their real paths.
func dellIDRACTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	root := loadDellIDRACFixture(t, "dell-idrac_2.65.65.65_root.json")
	mgr := loadDellIDRACFixture(t, "dell-idrac_2.65.65.65_manager.json")
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redfish/v1":
			_, _ = w.Write(root)
		case "/redfish/v1/Managers/iDRAC.Embedded.1":
			_, _ = w.Write(mgr)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestDellIDRACProbeParsesRealFixtures(t *testing.T) {
	srv := dellIDRACTestServer(t)
	defer srv.Close()

	p := dellIDRACProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "dell-idrac"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "2.65.65.65" {
		t.Fatalf("got version %q, want 2.65.65.65", obs.Version)
	}
	if obs.Extra["model"] != "12G Modular" {
		t.Fatalf("got Extra %+v, want model=\"12G Modular\"", obs.Extra)
	}
	if obs.Extra["serviceTag"] != "EXAMPLE1" {
		t.Fatalf("got Extra %+v, want serviceTag=EXAMPLE1", obs.Extra)
	}
}

// A real Supermicro BMC's service root carries no Oem.Dell key — must be
// rejected rather than silently parsed if a target is misdeclared.
func TestDellIDRACProbeRejectsNonDell(t *testing.T) {
	fixture := loadSupermicroBMCFixture(t, "supermicro-bmc_01.05.25.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/redfish/v1" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := dellIDRACProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "dell-idrac"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestDellIDRACProbeUnauthorizedIsErrAuth(t *testing.T) {
	// Confirmed live: a real iDRAC answers 401 without credentials on
	// both /redfish/v1 and the Managers resource.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := dellIDRACProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "dell-idrac"))
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestDellIDRACProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := dellIDRACProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "dell-idrac"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestDellIDRACProbeMeta(t *testing.T) {
	m := dellIDRACProbe{}.Meta()
	if m.Product != "dell-idrac" {
		t.Fatalf("got product %q", m.Product)
	}
	if !m.Auth.Required {
		t.Fatal("a real iDRAC needs credentials, confirmed live")
	}
	if m.DefaultResolver.Type != "" {
		t.Fatalf("got resolver %+v, want none (BMC firmware has no public lifecycle calendar)", m.DefaultResolver)
	}
}
