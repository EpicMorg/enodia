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

func loadOpenSearchFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "opensearch_3.8.0.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// opensearch_3.8.0.json is a real GET / reply captured from a live
// opensearchproject/opensearch container with security disabled
// (DISABLE_SECURITY_PLUGIN=true, a real documented setting).
func TestOpenSearchProbeParsesRealFixture(t *testing.T) {
	fixture := loadOpenSearchFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			t.Errorf("got path %q, want /", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := opensearchProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "opensearch"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "3.8.0" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["clusterName"] != "docker-cluster" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

// D9: product: opensearch pointed at a real Elasticsearch must fail, not
// silently report Elasticsearch's version as OpenSearch's. Uses the real
// elasticsearch fixture, which carries no version.distribution field.
func TestOpenSearchProbeRejectsRealElasticsearch(t *testing.T) {
	fixture := loadElasticsearchFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := opensearchProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "opensearch"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestOpenSearchProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := opensearchProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "opensearch"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestOpenSearchProbeMeta(t *testing.T) {
	m := opensearchProbe{}.Meta()
	if m.Product != "opensearch" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("DISABLE_SECURITY_PLUGIN=true is a real, documented anonymous deployment shape")
	}
	if !m.Auth.Accepts(AuthBasic) {
		t.Fatal("the default security posture uses HTTP Basic")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "opensearch" {
		t.Fatalf("got resolver %+v, want endoflife/opensearch", m.DefaultResolver)
	}
}
