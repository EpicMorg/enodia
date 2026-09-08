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

func loadKibanaFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "kibana_8.15.0.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// kibana_8.15.0.json is a real /api/status reply captured from a live
// docker.elastic.co/kibana/kibana container (backed by a real
// Elasticsearch), with no credentials at all — this endpoint is
// deliberately unauthenticated so orchestrators can use it as a liveness
// probe.
func TestKibanaProbeParsesRealFixture(t *testing.T) {
	fixture := loadKibanaFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/status" {
			t.Errorf("got path %q, want /api/status", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := kibanaProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "kibana"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "8.15.0" {
		t.Fatalf("got version %q", obs.Version)
	}
}

// Confirmed live: Kibana answers 503 ("Status not yet reported") while
// still starting up, but the body already carries the real version.
func TestKibanaProbe503StillReportsVersion(t *testing.T) {
	fixture := loadKibanaFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := kibanaProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "kibana"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "8.15.0" {
		t.Fatalf("got version %q", obs.Version)
	}
}

func TestKibanaProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := kibanaProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "kibana"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestKibanaProbeMissingVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"name":"x","uuid":"y"}`))
	}))
	defer srv.Close()

	p := kibanaProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "kibana"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestKibanaProbeMeta(t *testing.T) {
	m := kibanaProbe{}.Meta()
	if m.Product != "kibana" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("/api/status is deliberately unauthenticated by design")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "kibana" {
		t.Fatalf("got resolver %+v, want endoflife/kibana", m.DefaultResolver)
	}
}
