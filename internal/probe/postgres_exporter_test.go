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

func loadPostgresExporterFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "postgres_exporter_0.20.1.txt"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// postgres_exporter_0.20.1.txt is a real /metrics reply captured from a
// live prometheuscommunity/postgres-exporter container with no credentials
// at all — confirmed to answer even though its DATA_SOURCE_NAME pointed at
// nothing reachable, since build_info describes the exporter binary, not
// the database.
func TestPostgresExporterProbeParsesRealFixture(t *testing.T) {
	fixture := loadPostgresExporterFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			t.Errorf("got path %q, want /metrics", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := postgresExporterProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "postgres_exporter"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "0.20.1" {
		t.Fatalf("got version %q", obs.Version)
	}
}

// Label order is not guaranteed to be alphabetical by every exporter build;
// this exercises the pattern against a rearranged (and trimmed) line to
// confirm the regex has no positional assumption.
func TestPostgresExporterProbeLabelOrderIndependent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`postgres_exporter_build_info{revision="abc",version="0.15.0",branch="HEAD"} 1` + "\n"))
	}))
	defer srv.Close()

	p := postgresExporterProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "postgres_exporter"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "0.15.0" {
		t.Fatalf("got version %q", obs.Version)
	}
}

func TestPostgresExporterProbeMissingBuildInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("go_goroutines 9\n"))
	}))
	defer srv.Close()

	p := postgresExporterProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "postgres_exporter"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestPostgresExporterProbeMeta(t *testing.T) {
	m := postgresExporterProbe{}.Meta()
	if m.Product != "postgres_exporter" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("/metrics needs no credentials by default")
	}
	if !m.Auth.Accepts(AuthBasic) {
		t.Fatal("exporter-toolkit's web.config.file can add HTTP Basic")
	}
	if m.DefaultResolver.Type != "github" || m.DefaultResolver.ID != "prometheus-community/postgres_exporter" {
		t.Fatalf("got resolver %+v, want github/prometheus-community/postgres_exporter", m.DefaultResolver)
	}
}
