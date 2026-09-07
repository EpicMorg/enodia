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

func loadKeycloakFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "keycloak_26.7.3.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// keycloak_26.7.3.json is a real /admin/serverinfo reply captured from a
// live quay.io/keycloak/keycloak container (authenticated with a bearer
// token minted via the standard OpenID Connect password grant against
// realms/master), with server-local noise (serverTime, uptime, memory/CPU
// figures, osVersion) replaced by fixed placeholders — the parser only
// reads systemInfo.version and systemInfo.javaVersion.
func TestKeycloakProbeParsesRealFixture(t *testing.T) {
	fixture := loadKeycloakFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/serverinfo" {
			t.Errorf("got path %q, want /admin/serverinfo", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("got Authorization %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	tgt := target(srv.URL, "keycloak")
	tgt.Creds = Credentials{Kind: AuthBearer, Value: "test-token"}
	tgt.AllowInsecureTransport = true

	p := keycloakProbe{}
	obs, err := p.Probe(context.Background(), tgt)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "26.7.3" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["javaVersion"] != "21.0.12.1" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

// A fresh instance has no anonymous path to /admin/serverinfo at all —
// confirmed live, unlike TeamCity's optional guest access.
func TestKeycloakProbeUnauthorizedIsErrAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := keycloakProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "keycloak"))
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestKeycloakProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := keycloakProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "keycloak"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestKeycloakProbeMissingVersionField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"systemInfo":{"javaVersion":"21.0.12.1"}}`))
	}))
	defer srv.Close()

	p := keycloakProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "keycloak"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestKeycloakProbeMeta(t *testing.T) {
	m := keycloakProbe{}.Meta()
	if m.Product != "keycloak" {
		t.Fatalf("got product %q", m.Product)
	}
	if !m.Auth.Required {
		t.Fatal("Keycloak's admin API has no anonymous path, confirmed live: Required must be true")
	}
	if !m.Auth.Accepts(AuthBearer) {
		t.Fatal("expected AuthBearer to be accepted")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "keycloak" {
		t.Fatalf("got resolver %+v, want endoflife/keycloak", m.DefaultResolver)
	}
}
