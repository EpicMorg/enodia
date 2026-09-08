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

func loadJaegerFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "jaeger_1.76.0.html"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// jaeger_1.76.0.html is a real "/" reply captured from a live
// jaegertracing/all-in-one container with no credentials at all.
func TestJaegerProbeParsesRealFixture(t *testing.T) {
	fixture := loadJaegerFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			t.Errorf("got path %q, want /", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := jaegerProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "jaeger"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "v1.76.0" {
		t.Fatalf("got version %q", obs.Version)
	}
}

// A target behind an SSO gateway (oauth2-proxy, say) answers with the
// gateway's own page instead of Jaeger's — no JAEGER_VERSION anywhere.
func TestJaegerProbeBehindGatewayIsNotSupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>Sign in with Google</body></html>"))
	}))
	defer srv.Close()

	p := jaegerProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "jaeger"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestJaegerProbeEmptyGitVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`const JAEGER_VERSION = {"gitCommit":"","gitVersion":"","buildDate":""};`))
	}))
	defer srv.Close()

	p := jaegerProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "jaeger"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestJaegerProbeMeta(t *testing.T) {
	m := jaegerProbe{}.Meta()
	if m.Product != "jaeger" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("Jaeger has no authentication of its own at all")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "jaeger" {
		t.Fatalf("got resolver %+v, want endoflife/jaeger", m.DefaultResolver)
	}
}
