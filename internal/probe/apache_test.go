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

func loadApacheFixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return strings.TrimSpace(string(raw))
}

// apache_2.4.68_header.txt holds the exact "Server" header value seen on a
// real httpd:2.4 container's default page.
func TestApacheProbeParsesRealFixture(t *testing.T) {
	header := loadApacheFixture(t, "apache_2.4.68_header.txt")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			t.Errorf("got path %q, want /", r.URL.Path)
		}
		w.Header().Set("Server", header)
		w.Write([]byte("<html>ok</html>"))
	}))
	defer srv.Close()

	p := apacheProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "apache"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "2.4.68" {
		t.Fatalf("got version %q", obs.Version)
	}
}

func TestApacheProbe404StillReportsVersion(t *testing.T) {
	header := loadApacheFixture(t, "apache_2.4.68_header.txt")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", header)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p := apacheProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "apache"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "2.4.68" {
		t.Fatalf("got version %q", obs.Version)
	}
}

// ServerTokens Prod (confirmed live against a real httpd:2.4 container with
// that directive set) stamps a bare "Apache" with no version at all.
func TestApacheProbeServerTokensProd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Apache")
		w.Write([]byte("<html>ok</html>"))
	}))
	defer srv.Close()

	p := apacheProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "apache"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestApacheProbeWrongProduct(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.27.4")
		w.Write([]byte("<html>ok</html>"))
	}))
	defer srv.Close()

	p := apacheProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "apache"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestApacheProbeMeta(t *testing.T) {
	m := apacheProbe{}.Meta()
	if m.Product != "apache" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("the Server header needs no credentials")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "apache-http-server" {
		t.Fatalf("got resolver %+v, want endoflife/apache-http-server", m.DefaultResolver)
	}
}
