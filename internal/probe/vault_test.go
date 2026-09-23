// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadVaultFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// vault_2.1.0.json is a real /v1/sys/health reply from a live
// hashicorp/vault dev container, unsealed and active (HTTP 200) — with the
// random dev-mode cluster_name/cluster_id/server_time_utc replaced by fixed
// placeholders, since the parser only reads version/initialized/sealed/
// standby/cluster_name and none of those values are validated as such.
func TestVaultProbeUnsealedParsesRealFixture(t *testing.T) {
	fixture := loadVaultFixture(t, "vault_2.1.0.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/health" {
			t.Errorf("got path %q, want /v1/sys/health", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := vaultProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "vault"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "2.1.0" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["sealed"] != "false" || obs.Extra["standby"] != "false" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

// vault_2.1.0_sealed.json is the same container's real reply once sealed
// via its own /v1/sys/seal API — a 503, but still carrying version and
// state, confirmed live rather than assumed from the API reference alone.
func TestVaultProbeSealedIsNotAnError(t *testing.T) {
	fixture := loadVaultFixture(t, "vault_2.1.0_sealed.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := vaultProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "vault"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "2.1.0" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["sealed"] != "true" {
		t.Fatalf("got extra %+v, want sealed=true", obs.Extra)
	}
}

func TestVaultProbeDocumentedNonHealthyStatusesAreNotErrors(t *testing.T) {
	for _, status := range []int{429, 472, 473, 501, 503} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"version":"2.1.0","initialized":true,"sealed":false,"standby":true}`))
		}))
		p := vaultProbe{}
		obs, err := p.Probe(context.Background(), target(srv.URL, "vault"))
		srv.Close()
		if err != nil {
			t.Fatalf("status %d: Probe: %v", status, err)
		}
		if obs.Version != "2.1.0" {
			t.Fatalf("status %d: got version %q", status, obs.Version)
		}
	}
}

func TestVaultProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := vaultProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "vault"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestVaultProbeMissingVersionField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"initialized":true,"sealed":false}`))
	}))
	defer srv.Close()

	p := vaultProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "vault"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestVaultProbeMeta(t *testing.T) {
	m := vaultProbe{}.Meta()
	if m.Product != "vault" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("this endpoint is intentionally anonymous, confirmed live")
	}
	if len(m.Auth.Kinds) != 0 {
		t.Fatalf("got Kinds %+v, want none: X-Vault-Token made no difference to this endpoint live", m.Auth.Kinds)
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "hashicorp-vault" {
		t.Fatalf("got resolver %+v, want endoflife/hashicorp-vault", m.DefaultResolver)
	}
}

// The recorded reply is a community server ("enterprise": false). The
// Enterprise variant flips only that one real field of the same reply;
// an older Vault without the field reports no edition at all.
func TestVaultProbeReportsEdition(t *testing.T) {
	fixture := string(loadVaultFixture(t, "vault_2.1.0.json"))
	for _, c := range []struct {
		name, body, want string
		present          bool
	}{
		{"community (real)", fixture, "false", true},
		{"enterprise", strings.Replace(fixture, `"enterprise": false`, `"enterprise": true`, 1), "true", true},
		{"field absent", strings.Replace(fixture, `"enterprise": false,`, ``, 1), "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()
			obs, err := vaultProbe{}.Probe(context.Background(), target(srv.URL, "vault"))
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			got, present := obs.Extra["enterprise"]
			if got != c.want || present != c.present {
				t.Fatalf("got enterprise=%q present=%v, want %q present=%v", got, present, c.want, c.present)
			}
		})
	}
}
