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

func loadGrafanaFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "grafana_13.2.1.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// grafana_13.2.1.json is a real /api/health reply captured from a live
// grafana/grafana container.
func TestGrafanaProbeParsesRealFixture(t *testing.T) {
	fixture := loadGrafanaFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/health" {
			t.Errorf("got path %q, want /api/health", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := grafanaProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "grafana"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "13.2.1" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["database"] != "ok" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
	if obs.Extra["commit"] != "56cd3e9288d8255fecebe5d05b48d191f50674b5" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

func TestGrafanaProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := grafanaProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "grafana"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestGrafanaProbeMissingVersionField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"database":"ok"}`))
	}))
	defer srv.Close()

	p := grafanaProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "grafana"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestGrafanaProbeMeta(t *testing.T) {
	m := grafanaProbe{}.Meta()
	if m.Product != "grafana" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("this endpoint is intentionally public, confirmed live")
	}
	if len(m.Auth.Kinds) != 0 {
		t.Fatalf("got Kinds %+v, want none: wrong Basic auth credentials still got a 200 live", m.Auth.Kinds)
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "grafana" {
		t.Fatalf("got resolver %+v, want endoflife/grafana", m.DefaultResolver)
	}
}
