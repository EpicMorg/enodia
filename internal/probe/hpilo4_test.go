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

func loadHPILO4Fixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "hp-ilo4_2.82.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// hp-ilo4_2.82.json is a real GET /redfish/v1/Managers/1/ reply captured
// from a live HP iLO 4 controller.
func TestHPILO4ProbeParsesRealFixture(t *testing.T) {
	fixture := loadHPILO4Fixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/redfish/v1/Managers/1/" {
			t.Errorf("got path %q, want /redfish/v1/Managers/1/", r.URL.Path)
		}
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := hpILO4Probe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "hp-ilo4"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "2.82" {
		t.Fatalf("got version %q, want 2.82", obs.Version)
	}
	if obs.Extra["raw"] != "iLO 4 v2.82" {
		t.Fatalf("got Extra %+v, want raw=\"iLO 4 v2.82\"", obs.Extra)
	}
}

// A real Supermicro BMC reply carries no Oem.Hp key — must be rejected
// rather than silently parsed if a target is misdeclared.
func TestHPILO4ProbeRejectsNonHP(t *testing.T) {
	fixture := loadSupermicroBMCFixture(t, "supermicro-bmc_01.05.25.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := hpILO4Probe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "hp-ilo4"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestHPILO4ProbeUnauthorizedIsErrAuth(t *testing.T) {
	// Confirmed live: a real iLO 4 answers 401 without credentials on
	// this exact resource.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := hpILO4Probe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "hp-ilo4"))
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestHPILO4ProbeUnrecognizedFirmwareString(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"FirmwareVersion":"unexpected","Oem":{"Hp":{}}}`))
	}))
	defer srv.Close()

	p := hpILO4Probe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "hp-ilo4"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestHPILO4ProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := hpILO4Probe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "hp-ilo4"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestHPILO4ProbeMeta(t *testing.T) {
	m := hpILO4Probe{}.Meta()
	if m.Product != "hp-ilo4" {
		t.Fatalf("got product %q", m.Product)
	}
	if !m.Auth.Required {
		t.Fatal("a real iLO 4 needs credentials, confirmed live")
	}
	if m.DefaultResolver.Type != "" {
		t.Fatalf("got resolver %+v, want none (BMC firmware has no public lifecycle calendar)", m.DefaultResolver)
	}
}
