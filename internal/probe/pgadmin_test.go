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

func loadPgadminFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "pgadmin_9.17.html"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// pgadmin_9.17.html is a real "/login" reply captured from a live
// dpage/pgadmin4 container with no credentials at all — the login page is
// inherently public. The CSRF token has been scrubbed.
func TestPgadminProbeParsesRealFixture(t *testing.T) {
	fixture := loadPgadminFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" {
			t.Errorf("got path %q, want /login", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := pgadminProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "pgadmin"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "9.17" {
		t.Fatalf("got version %q", obs.Version)
	}
	if len(obs.Extra) != 0 {
		t.Fatalf("got extra %+v, want none (GA build, suffix code 0)", obs.Extra)
	}
}

// A nonzero suffix code (a beta/dev build) has no documented text mapping
// to reconstruct, so it surfaces in Extra rather than being guessed at or
// silently dropped.
func TestPgadminProbeNonzeroSuffixSurfacesInExtra(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<script src="/static/js/generated/pgadmin_commons.js?ver=91701"></script>`))
	}))
	defer srv.Close()

	p := pgadminProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "pgadmin"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "9.17" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["suffixCode"] != "1" {
		t.Fatalf("got extra %+v, want suffixCode=1", obs.Extra)
	}
}

func TestPgadminProbeWrongProduct(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>not pgadmin at all</body></html>"))
	}))
	defer srv.Close()

	p := pgadminProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "pgadmin"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestPgadminProbeMeta(t *testing.T) {
	m := pgadminProbe{}.Meta()
	if m.Product != "pgadmin" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("the login page needs no credentials")
	}
	want := ResolverRef{Type: "github-tags", ID: "pgadmin-org/pgadmin4"}
	if m.DefaultResolver != want {
		t.Fatalf("got resolver %+v, want %+v", m.DefaultResolver, want)
	}
}
