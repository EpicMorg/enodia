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

func loadOAuth2ProxyFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "oauth2-proxy_7.15.4.html"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// oauth2-proxy_7.15.4.html is a real /oauth2/sign_in page captured from a
// live oauth2-proxy/oauth2-proxy container with no credentials at all — the
// sign-in page is inherently public.
func TestOAuth2ProxyProbeParsesRealFixture(t *testing.T) {
	fixture := loadOAuth2ProxyFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/sign_in" {
			t.Errorf("got path %q, want /oauth2/sign_in", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := oauth2ProxyProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "oauth2-proxy"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "v7.15.4" {
		t.Fatalf("got version %q", obs.Version)
	}
}

// --footer "-" (or any custom text) replaces the default line this probe
// looks for. Confirmed in pkg/app/pagewriter/sign_in.html's template
// source: `{{ if eq .Footer "-" }}` renders nothing at all in that case.
func TestOAuth2ProxyProbeCustomFooterIsNotSupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><body><footer></footer></body></html>`))
	}))
	defer srv.Close()

	p := oauth2ProxyProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "oauth2-proxy"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestOAuth2ProxyProbeWrongProduct(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><body>not oauth2-proxy at all</body></html>`))
	}))
	defer srv.Close()

	p := oauth2ProxyProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "oauth2-proxy"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestOAuth2ProxyProbeMeta(t *testing.T) {
	m := oauth2ProxyProbe{}.Meta()
	if m.Product != "oauth2-proxy" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("the sign-in page is inherently public")
	}
	if m.DefaultResolver.Type != "" {
		t.Fatalf("got resolver %+v, want none — endoflife.date has no oauth2-proxy calendar yet", m.DefaultResolver)
	}
}
