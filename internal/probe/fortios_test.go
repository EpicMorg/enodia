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

func loadFortiosFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "fortios_v7.4.12.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// fortios_v7.4.12.json is a real /api/v2/monitor/system/status reply
// captured from a live FortiGate 601E appliance, authenticated with a
// REST API Admin's bearer token, with the real serial number and hostname
// replaced by fixed placeholders — the parser only reads version, build
// and results.model.
func TestFortiosProbeParsesRealFixture(t *testing.T) {
	fixture := loadFortiosFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/monitor/system/status" {
			t.Errorf("got path %q, want /api/v2/monitor/system/status", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("got Authorization %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	tgt := target(srv.URL, "fortios")
	tgt.Creds = Credentials{Kind: AuthBearer, Value: "test-token"}
	tgt.AllowInsecureTransport = true

	p := fortiosProbe{}
	obs, err := p.Probe(context.Background(), tgt)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "v7.4.12" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["model"] != "FG6H1E" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
	if obs.Extra["build"] != "2902" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

// A missing or wrong REST API token answers HTTP 401 with an Apache-style
// HTML error page, not JSON — confirmed live. FetchHTTP already turns
// 401/403 into ErrAuth before this probe ever sees the body.
func TestFortiosProbeUnauthorizedIsErrAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("<html><body><h1>Unauthorized</h1></body></html>"))
	}))
	defer srv.Close()

	tgt := target(srv.URL, "fortios")
	tgt.Creds = Credentials{Kind: AuthBearer, Value: "wrong-token"}
	tgt.AllowInsecureTransport = true

	p := fortiosProbe{}
	_, err := p.Probe(context.Background(), tgt)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestFortiosProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	tgt := target(srv.URL, "fortios")
	tgt.Creds = Credentials{Kind: AuthBearer, Value: "test-token"}
	tgt.AllowInsecureTransport = true

	p := fortiosProbe{}
	_, err := p.Probe(context.Background(), tgt)
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestFortiosProbeMissingVersionField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","build":2902}`))
	}))
	defer srv.Close()

	tgt := target(srv.URL, "fortios")
	tgt.Creds = Credentials{Kind: AuthBearer, Value: "test-token"}
	tgt.AllowInsecureTransport = true

	p := fortiosProbe{}
	_, err := p.Probe(context.Background(), tgt)
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestFortiosProbeMeta(t *testing.T) {
	m := fortiosProbe{}.Meta()
	if m.Product != "fortios" {
		t.Fatalf("got product %q", m.Product)
	}
	if !m.Auth.Required {
		t.Fatal("FortiOS's REST API has no anonymous path, confirmed live: Required must be true")
	}
	if !m.Auth.Accepts(AuthBearer) {
		t.Fatal("expected AuthBearer to be accepted")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "fortios" {
		t.Fatalf("got resolver %+v, want endoflife/fortios", m.DefaultResolver)
	}
}
