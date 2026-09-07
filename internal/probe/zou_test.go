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

func loadZouFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "zou_1.0.56.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// zou_1.0.56.json is a real /api/status reply captured from a live
// production instance reachable at a "kitsu"-named host — the response
// itself says "name":"Zou", confirming Zou (the backend), not Kitsu (the
// frontend), is what actually answers this endpoint.
func TestZouProbeParsesRealFixture(t *testing.T) {
	fixture := loadZouFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/status" {
			t.Errorf("got path %q, want /api/status", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := zouProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "zou"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "1.0.56" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["databaseUp"] != "true" || obs.Extra["indexerUp"] != "true" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

func TestZouProbeWrongNameIsErrNotSupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"name":"SomethingElse","version":"1.0.0"}`))
	}))
	defer srv.Close()

	p := zouProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "zou"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestZouProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := zouProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "zou"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestZouProbeMissingVersionField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"name":"Zou"}`))
	}))
	defer srv.Close()

	p := zouProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "zou"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestZouProbeMeta(t *testing.T) {
	m := zouProbe{}.Meta()
	if m.Product != "zou" {
		t.Fatalf("got product %q", m.Product)
	}
	if len(m.Aliases) != 1 || m.Aliases[0] != "kitsu" {
		t.Fatalf("got aliases %+v, want [\"kitsu\"]", m.Aliases)
	}
	if m.Auth.Required {
		t.Fatal("this endpoint is intentionally public, confirmed live")
	}
	if m.DefaultResolver.Type != "" {
		t.Fatalf("got resolver %+v, want none (endoflife.date has no zou/kitsu calendar)", m.DefaultResolver)
	}
}

func TestZouAliasResolves(t *testing.T) {
	p, err := Get("kitsu")
	if err != nil {
		t.Fatalf("Get(\"kitsu\"): %v", err)
	}
	if p.Meta().Product != "zou" {
		t.Fatalf("got product %q via kitsu alias, want zou", p.Meta().Product)
	}
}
