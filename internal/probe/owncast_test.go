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

func loadOwncastFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "owncast_0.3.0.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// owncast_0.3.0.json is a real /api/status reply captured from a live
// owncast/owncast:latest container — the field shape was worked out from
// Owncast's own source first (webserver/handlers/status.go's
// webStatusResponse) since neither production instance this probe was
// drafted against was reachable, then confirmed against this container.
func TestOwncastProbeParsesFixture(t *testing.T) {
	fixture := loadOwncastFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/status" {
			t.Errorf("got path %q, want /api/status", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := owncastProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "owncast"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "0.3.0" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["online"] != "false" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

func TestOwncastProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := owncastProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "owncast"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestOwncastProbeMissingVersionField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"online":false}`))
	}))
	defer srv.Close()

	p := owncastProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "owncast"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestOwncastProbeMeta(t *testing.T) {
	m := owncastProbe{}.Meta()
	if m.Product != "owncast" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("GetStatus is called with no auth-requiring middleware in Owncast's own source")
	}
	if len(m.Auth.Kinds) != 0 {
		t.Fatalf("got Kinds %+v, want none: no credentialed path was ever tested", m.Auth.Kinds)
	}
	if m.DefaultResolver.Type != "" {
		t.Fatalf("got resolver %+v, want none (endoflife.date has no owncast calendar)", m.DefaultResolver)
	}
}
