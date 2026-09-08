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

// truenas_25.10.7.json is a real /api/v2.0/system/info reply captured from
// a live TrueNAS 25.10.7 host, authenticated with an API key
// (system_serial scrubbed; every other field is real).
func loadTrueNASFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "truenas_25.10.7.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

func TestTrueNASProbeParsesRealFixture(t *testing.T) {
	fixture := loadTrueNASFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2.0/system/info" {
			t.Errorf("got path %q, want /api/v2.0/system/info", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-api-key" {
			t.Errorf("got Authorization %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := truenasProbe{}
	tgt := target(srv.URL, "truenas")
	tgt.Creds = Credentials{Kind: AuthBearer, Value: "test-api-key"}
	tgt.AllowInsecureTransport = true

	obs, err := p.Probe(context.Background(), tgt)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "25.10.7" {
		t.Fatalf("got version %q", obs.Version)
	}
}

// A fresh TrueNAS host answers exactly this way: 401 for any request
// carrying no valid API key — confirmed live against a real 25.10.7 host.
func TestTrueNASProbeUnauthorizedIsErrAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := truenasProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "truenas"))
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestTrueNASProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := truenasProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "truenas"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestTrueNASProbeMissingVersionField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"hostname":"truenas"}`))
	}))
	defer srv.Close()

	p := truenasProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "truenas"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestTrueNASProbeMeta(t *testing.T) {
	m := truenasProbe{}.Meta()
	if m.Product != "truenas" {
		t.Fatalf("got product %q", m.Product)
	}
	if !m.Auth.Required {
		t.Fatal("truenas requires authentication")
	}
	if !m.Auth.Accepts(AuthBearer) {
		t.Fatal("expected bearer to be accepted")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "truenas" {
		t.Fatalf("got resolver %+v", m.DefaultResolver)
	}
}
