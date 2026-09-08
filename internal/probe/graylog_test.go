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

func loadGraylogFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "graylog_4.3.15.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// graylog_4.3.15.json is a real /api/ reply captured from a live
// graylog/graylog container (plus the MongoDB and Elasticsearch it
// depends on) with no credentials at all.
func TestGraylogProbeParsesRealFixture(t *testing.T) {
	fixture := loadGraylogFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/" {
			t.Errorf("got path %q, want /api/", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := graylogProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "graylog"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "4.3.15+17ed3ac" {
		t.Fatalf("got version %q", obs.Version)
	}
}

func TestGraylogProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := graylogProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "graylog"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestGraylogProbeMissingVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"cluster_id":"x","node_id":"y"}`))
	}))
	defer srv.Close()

	p := graylogProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "graylog"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestGraylogProbeMeta(t *testing.T) {
	m := graylogProbe{}.Meta()
	if m.Product != "graylog" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("the REST API root is a public discovery document")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "graylog" {
		t.Fatalf("got resolver %+v, want endoflife/graylog", m.DefaultResolver)
	}
}
