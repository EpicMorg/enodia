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

func loadYouTrackFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "youtrack_2026.3.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// youtrack_2026.3.json is a real /api/config?fields=version reply captured
// from a live, internet-facing YouTrack instance with no credentials at all
// — an anonymous caller gets nothing back but the version.
func TestYouTrackProbeParsesRealFixture(t *testing.T) {
	fixture := loadYouTrackFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/config" {
			t.Errorf("got path %q, want /api/config", r.URL.Path)
		}
		if got := r.URL.RawQuery; got != "fields=version" {
			t.Errorf("got query %q, want fields=version", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := youtrackProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "youtrack"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "2026.3" {
		t.Fatalf("got version %q", obs.Version)
	}
}

func TestYouTrackProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := youtrackProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "youtrack"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestYouTrackProbeMissingVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"$type":"FrontendConfig"}`))
	}))
	defer srv.Close()

	p := youtrackProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "youtrack"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestYouTrackProbeWrongPathIsNotSupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()

	p := youtrackProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "youtrack"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestYouTrackProbeMeta(t *testing.T) {
	m := youtrackProbe{}.Meta()
	if m.Product != "youtrack" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("the config endpoint is documented and confirmed to work anonymously")
	}
	if !m.Auth.Accepts(AuthBearer) {
		t.Fatal("YouTrack's own docs specify Authorization: Bearer perm:... for permanent tokens")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "youtrack" {
		t.Fatalf("got resolver %+v, want endoflife/youtrack", m.DefaultResolver)
	}
}
