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

func loadHAProxyFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "haproxy_3.0.27.html"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// haproxy_3.0.27.html is a real /stats page captured from a live
// haproxy:3.0 container with `stats enable` and no `stats auth` at all.
func TestHAProxyProbeParsesRealFixture(t *testing.T) {
	fixture := loadHAProxyFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stats" {
			t.Errorf("got path %q, want /stats", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := haproxyProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "haproxy"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "3.0.27-a2b09cd" {
		t.Fatalf("got version %q", obs.Version)
	}
}

// A 200 response with no "HAProxy version ..." heading at all — either the
// wrong product behind this address, or (HAProxy has no custom stats
// templating) an address that answers 200 for an unrelated reason.
func TestHAProxyProbeWrongProductIsNotSupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>not haproxy at all</body></html>"))
	}))
	defer srv.Close()

	p := haproxyProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "haproxy"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

// Confirmed live: a 503 from HAProxy's own "no server available" default
// error page (the shape a wrong stats path or an unconfigured frontend
// takes) carries no version text either, so there is nothing this probe
// could recover from it regardless — the generic >=400 handling in
// FetchHTTP (ErrUnreachable) applies same as for any other probe.
func TestHAProxyProbe503IsUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("<html><body><h1>503 Service Unavailable</h1>\nNo server is available to handle this request.\n</body></html>"))
	}))
	defer srv.Close()

	p := haproxyProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "haproxy"))
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}
}

func TestHAProxyProbeMeta(t *testing.T) {
	m := haproxyProbe{}.Meta()
	if m.Product != "haproxy" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("stats enable with no stats auth needs no credentials")
	}
	if !m.Auth.Accepts(AuthBasic) {
		t.Fatal("HAProxy's own `stats auth user:pass` is ordinary HTTP Basic")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "haproxy" {
		t.Fatalf("got resolver %+v, want endoflife/haproxy", m.DefaultResolver)
	}
}
