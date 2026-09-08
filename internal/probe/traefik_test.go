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

func loadTraefikFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "traefik_3.1.7.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// traefik_3.1.7.json is a real /api/version reply captured from a live
// traefik:v3.1 container run with --api.insecure=true, with no credentials
// at all.
func TestTraefikProbeParsesRealFixture(t *testing.T) {
	fixture := loadTraefikFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/version" {
			t.Errorf("got path %q, want /api/version", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := traefikProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "traefik"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "3.1.7" {
		t.Fatalf("got version %q", obs.Version)
	}
}

// The API router is off by default (neither --api nor --api.insecure set on
// a stock instance) — confirmed live, a stock traefik:v3.1 container
// answers plain 404 here.
func TestTraefikProbeAPIDisabledIsNotSupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()

	p := traefikProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "traefik"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestTraefikProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := traefikProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "traefik"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestTraefikProbeMissingVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Codename":"comte"}`))
	}))
	defer srv.Close()

	p := traefikProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "traefik"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestTraefikProbeMeta(t *testing.T) {
	m := traefikProbe{}.Meta()
	if m.Product != "traefik" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("--api.insecure=true needs no credentials")
	}
	if !m.Auth.Accepts(AuthBasic) {
		t.Fatal("a secured API router uses ordinary HTTP Basic")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "traefik" {
		t.Fatalf("got resolver %+v, want endoflife/traefik", m.DefaultResolver)
	}
}
