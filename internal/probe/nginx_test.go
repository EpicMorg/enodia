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

func loadNginxFixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return strings.TrimSpace(string(raw))
}

// nginx_1.27.4_header.txt holds the exact "Server" header value seen on a
// real nginx:1.27.4 container's default page.
func TestNginxProbeParsesRealFixture(t *testing.T) {
	header := loadNginxFixture(t, "nginx_1.27.4_header.txt")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			t.Errorf("got path %q, want /", r.URL.Path)
		}
		w.Header().Set("Server", header)
		w.Write([]byte("<html>ok</html>"))
	}))
	defer srv.Close()

	p := nginxProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "nginx"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "1.27.4" {
		t.Fatalf("got version %q", obs.Version)
	}
}

// A 404 (nothing served at "/", a common real-world shape for a vhost that
// only answers on other paths) still carries nginx's own Server header —
// confirmed live — so this must not fail.
func TestNginxProbe404StillReportsVersion(t *testing.T) {
	header := loadNginxFixture(t, "nginx_1.27.4_header.txt")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", header)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p := nginxProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "nginx"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "1.27.4" {
		t.Fatalf("got version %q", obs.Version)
	}
}

// server_tokens off (confirmed live against a real nginx:1.27.4 container
// with that directive set) stamps a bare "nginx" with no version at all.
func TestNginxProbeServerTokensOff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Write([]byte("<html>ok</html>"))
	}))
	defer srv.Close()

	p := nginxProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "nginx"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestNginxProbeWrongProduct(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		w.Write([]byte("<html>ok</html>"))
	}))
	defer srv.Close()

	p := nginxProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "nginx"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestNginxProbeNoServerHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Del("Server")
		w.Write([]byte("<html>ok</html>"))
	}))
	defer srv.Close()

	p := nginxProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "nginx"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestNginxProbeMeta(t *testing.T) {
	m := nginxProbe{}.Meta()
	if m.Product != "nginx" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("the Server header needs no credentials")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "nginx" {
		t.Fatalf("got resolver %+v, want endoflife/nginx", m.DefaultResolver)
	}
}
