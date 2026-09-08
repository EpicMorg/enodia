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

func loadRouterOSFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "routeros_7.24.2.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// routeros_7.24.2.json is a real /rest/system/resource reply captured
// from a live CHR (Cloud Hosted Router) 7.24.2 VM booted under QEMU, with
// the default admin user and no password.
func TestRouterOSProbeParsesRealFixture(t *testing.T) {
	fixture := loadRouterOSFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/system/resource" {
			t.Errorf("got path %q, want /rest/system/resource", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := routerosProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "routeros"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "7.24.2 (stable)" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["architecture"] != "x86_64" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

// Confirmed live: this endpoint always answers 401 without credentials —
// there is no anonymous path on RouterOS's REST API at all.
func TestRouterOSProbeUnauthorizedIsErrAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", "Basic")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":401,"message":"Unauthorized"}`))
	}))
	defer srv.Close()

	p := routerosProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "routeros"))
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestRouterOSProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := routerosProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "routeros"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestRouterOSProbeMeta(t *testing.T) {
	m := routerosProbe{}.Meta()
	if m.Product != "routeros" {
		t.Fatalf("got product %q", m.Product)
	}
	if !m.Auth.Required {
		t.Fatal("RouterOS's REST API has no anonymous path at all, confirmed live")
	}
	if !m.Auth.Accepts(AuthBasic) {
		t.Fatal("confirmed live: HTTP Basic works")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "routeros" {
		t.Fatalf("got resolver %+v, want endoflife/routeros", m.DefaultResolver)
	}
}
