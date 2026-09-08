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

func loadNexusFixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return strings.TrimSpace(string(raw))
}

// nexus_3.96.0-09_header.txt holds the exact "Server" header value seen on
// a real sonatype/nexus3 container's status endpoint.
func TestNexusProbeParsesRealFixture(t *testing.T) {
	header := loadNexusFixture(t, "nexus_3.96.0-09_header.txt")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/service/rest/v1/status" {
			t.Errorf("got path %q, want /service/rest/v1/status", r.URL.Path)
		}
		w.Header().Set("Server", header)
		w.Write(nil)
	}))
	defer srv.Close()

	p := nexusProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "nexus"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "3.96.0-09" {
		t.Fatalf("got version %q", obs.Version)
	}
}

func TestNexusProbeWrongProduct(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Apache/2.4.68 (Unix)")
		w.Write(nil)
	}))
	defer srv.Close()

	p := nexusProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "nexus"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestNexusProbeNoVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Nexus")
		w.Write(nil)
	}))
	defer srv.Close()

	p := nexusProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "nexus"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestNexusProbeMeta(t *testing.T) {
	m := nexusProbe{}.Meta()
	if m.Product != "nexus" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("the status endpoint needs no credentials")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "nexus" {
		t.Fatalf("got resolver %+v, want endoflife/nexus", m.DefaultResolver)
	}
}
