// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func loadZabbixFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "zabbix_7.4.10.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// zabbix_7.4.10.json is a real apiinfo.version reply captured from a live,
// internet-facing Zabbix frontend — the method takes no credentials and
// carries nothing but a version string, so there is nothing in the fixture
// to scrub.
func TestZabbixProbeParsesRealFixture(t *testing.T) {
	fixture := loadZabbixFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api_jsonrpc.php" {
			t.Errorf("got path %q, want /api_jsonrpc.php", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("got method %q, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("got Content-Type %q, want application/json", got)
		}
		body, _ := io.ReadAll(r.Body)
		if got := string(body); got != `{"jsonrpc":"2.0","method":"apiinfo.version","params":{},"id":1}` {
			t.Errorf("got request body %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := zabbixProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "zabbix"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "7.4.10" {
		t.Fatalf("got version %q", obs.Version)
	}
}

func TestZabbixProbeJSONRPCError(t *testing.T) {
	// Not observed live: apiinfo.version is not documented to ever error.
	// This exercises the envelope's error branch so a future API change
	// (or a non-Zabbix server behind the address) fails as ErrUnparseable
	// rather than silently reporting an empty version as success.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found."},"id":1}`))
	}))
	defer srv.Close()

	p := zabbixProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "zabbix"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestZabbixProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := zabbixProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "zabbix"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestZabbixProbeMissingResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1}`))
	}))
	defer srv.Close()

	p := zabbixProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "zabbix"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

// A bare GET is what a misconfigured target (or the wrong port) most often
// looks like; confirmed live that Zabbix itself answers GET on this endpoint
// with 412, not a version — this only pins that FetchHTTP's generic
// >=400-is-a-failure handling covers it, since zabbixProbe adds nothing
// method-specific of its own beyond always sending POST.
func TestZabbixProbeWrongPathIsNotSupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()

	p := zabbixProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "zabbix"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestZabbixProbeMeta(t *testing.T) {
	m := zabbixProbe{}.Meta()
	if m.Product != "zabbix" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("apiinfo.version is documented to need no authentication")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "zabbix" {
		t.Fatalf("got resolver %+v, want endoflife/zabbix", m.DefaultResolver)
	}
}
