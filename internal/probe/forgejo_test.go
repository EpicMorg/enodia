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

func loadForgejoFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "forgejo_9.0.3.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// forgejo_9.0.3.json is a real /api/v1/version reply captured from a live
// codeberg.org/forgejo/forgejo container with no credentials at all.
func TestForgejoProbeParsesRealFixture(t *testing.T) {
	fixture := loadForgejoFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/version" {
			t.Errorf("got path %q, want /api/v1/version", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := forgejoProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "forgejo"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "9.0.3+gitea-1.22.0" {
		t.Fatalf("got version %q", obs.Version)
	}
}

// REQUIRE_SIGNIN_VIEW = true (a real Forgejo hardening option, confirmed
// live) answers 403 on this endpoint too.
func TestForgejoProbeRequireSigninViewIsErrAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Only signed in user is allowed to call APIs."}`))
	}))
	defer srv.Close()

	p := forgejoProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "forgejo"))
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestForgejoProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := forgejoProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "forgejo"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestForgejoProbeMeta(t *testing.T) {
	m := forgejoProbe{}.Meta()
	if m.Product != "forgejo" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("anonymous by default; REQUIRE_SIGNIN_VIEW is opt-in")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "forgejo" {
		t.Fatalf("got resolver %+v, want endoflife/forgejo", m.DefaultResolver)
	}
}
