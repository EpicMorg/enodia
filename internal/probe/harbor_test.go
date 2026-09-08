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

func loadHarborFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "harbor_2.12.2.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// harbor_2.12.2.json is a real /api/v2.0/systeminfo reply captured from a
// live goharbor/harbor v2.12.2 stack (installed via the official
// docker-compose installer), with no credentials at all.
func TestHarborProbeParsesRealFixture(t *testing.T) {
	fixture := loadHarborFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2.0/systeminfo" {
			t.Errorf("got path %q, want /api/v2.0/systeminfo", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := harborProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "harbor"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "v2.12.2-73072d0d" {
		t.Fatalf("got version %q", obs.Version)
	}
}

// Confirmed live: bad or fabricated credentials never get a 401 from this
// endpoint, they are just treated as anonymous.
func TestHarborProbeMissingVersionIsNotSupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"auth_mode":"db_auth","self_registration":false}`))
	}))
	defer srv.Close()

	p := harborProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "harbor"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestHarborProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := harborProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "harbor"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestHarborProbeMeta(t *testing.T) {
	m := harborProbe{}.Meta()
	if m.Product != "harbor" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("every currently-released Harbor version answers this anonymously")
	}
	if !m.Auth.Accepts(AuthBasic) {
		t.Fatal("Harbor's own API auth scheme is HTTP Basic")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "harbor" {
		t.Fatalf("got resolver %+v, want endoflife/harbor", m.DefaultResolver)
	}
}
