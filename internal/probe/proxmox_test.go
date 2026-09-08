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

// proxmox_9.2.2.json is a real /api2/json/version reply captured from a
// live Proxmox VE 9.2.2 host, authenticated with an API token.
func loadProxmoxFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "proxmox_9.2.2.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

func TestProxmoxProbeParsesRealFixture(t *testing.T) {
	fixture := loadProxmoxFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api2/json/version" {
			t.Errorf("got path %q, want /api2/json/version", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "PVEAPIToken=root@pam!test=secret" {
			t.Errorf("got Authorization %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := proxmoxProbe{}
	tgt := target(srv.URL, "proxmox")
	tgt.Creds = Credentials{Kind: AuthTokenHeader, Value: "PVEAPIToken=root@pam!test=secret"}
	tgt.AllowInsecureTransport = true

	obs, err := p.Probe(context.Background(), tgt)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "9.2.2" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["repoid"] != "b9984c6d90a4bd80" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

// A fresh Proxmox VE host answers exactly this way: 401 with no body, for
// any request carrying no valid token — confirmed live against a real
// 9.2.2 host.
func TestProxmoxProbeUnauthorizedIsErrAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := proxmoxProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "proxmox"))
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestProxmoxProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := proxmoxProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "proxmox"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestProxmoxProbeMissingVersionField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"release":"9.2"}}`))
	}))
	defer srv.Close()

	p := proxmoxProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "proxmox"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestProxmoxProbeMeta(t *testing.T) {
	m := proxmoxProbe{}.Meta()
	if m.Product != "proxmox" {
		t.Fatalf("got product %q", m.Product)
	}
	if !m.Auth.Required {
		t.Fatal("proxmox requires authentication")
	}
	if !m.Auth.Accepts(AuthTokenHeader) {
		t.Fatal("expected token-header to be accepted")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "proxmox-ve" {
		t.Fatalf("got resolver %+v", m.DefaultResolver)
	}
}
