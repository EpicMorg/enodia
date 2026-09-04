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

func loadPortainerFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "portainer_2.45.0.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// portainer_2.45.0.json is a real /api/system/status reply captured from a
// live portainer/portainer-ce container, with the random per-install
// InstanceID replaced by a fixed placeholder — the parser only reads
// Version/InstanceID, and InstanceID is just echoed back, not validated.
func TestPortainerProbeParsesRealFixture(t *testing.T) {
	fixture := loadPortainerFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/system/status" {
			t.Errorf("got path %q, want /api/system/status", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := portainerProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "portainer"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "2.45.0" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["instanceId"] == "" {
		t.Fatalf("got extra %+v, want a non-empty instanceId", obs.Extra)
	}
}

func TestPortainerProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := portainerProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "portainer"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestPortainerProbeMissingVersionField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"InstanceID":"x"}`))
	}))
	defer srv.Close()

	p := portainerProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "portainer"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestPortainerProbeMeta(t *testing.T) {
	m := portainerProbe{}.Meta()
	if m.Product != "portainer" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("this endpoint is intentionally public, confirmed live: it answers before an admin account even exists")
	}
	if len(m.Auth.Kinds) != 0 {
		t.Fatalf("got Kinds %+v, want none: no credentialed path was ever tested", m.Auth.Kinds)
	}
	if m.DefaultResolver.Type != "" {
		t.Fatalf("got resolver %+v, want none (endoflife.date has no portainer calendar)", m.DefaultResolver)
	}
}
