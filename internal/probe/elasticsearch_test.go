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

func loadElasticsearchFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "elasticsearch_9.5.3.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// elasticsearch_9.5.3.json is a real GET / reply captured from a live
// docker.elastic.co/elasticsearch/elasticsearch container (authenticated
// with the elastic superuser, its password reset via the image's own
// elasticsearch-reset-password tool), with the random node "name" and
// "cluster_uuid" replaced by fixed placeholders — the parser only reads
// cluster_name/version.number/version.lucene_version/version.build_hash.
func TestElasticsearchProbeParsesRealFixture(t *testing.T) {
	fixture := loadElasticsearchFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			t.Errorf("got path %q, want /", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := elasticsearchProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "elasticsearch"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "9.5.3" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["clusterName"] != "docker-cluster" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
	if obs.Extra["luceneVersion"] != "10.5.1" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

func TestElasticsearchProbeUnauthorizedIsErrAuth(t *testing.T) {
	// Security is on by default since 8.0: a fresh instance answers 401
	// advertising Basic, Bearer and ApiKey — confirmed live, not assumed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("WWW-Authenticate", `Basic realm="security", charset="UTF-8"`)
		w.Header().Add("WWW-Authenticate", `Bearer realm="security"`)
		w.Header().Add("WWW-Authenticate", `ApiKey`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := elasticsearchProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "elasticsearch"))
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestElasticsearchProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := elasticsearchProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "elasticsearch"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestElasticsearchProbeMissingVersionField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"cluster_name":"docker-cluster"}`))
	}))
	defer srv.Close()

	p := elasticsearchProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "elasticsearch"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestElasticsearchProbeMeta(t *testing.T) {
	m := elasticsearchProbe{}.Meta()
	if m.Product != "elasticsearch" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("xpack.security.enabled=false is a real, documented configuration confirmed live: credentials are not always required")
	}
	if !m.Auth.Accepts(AuthBasic) {
		t.Fatal("expected AuthBasic to be accepted")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "elasticsearch" {
		t.Fatalf("got resolver %+v, want endoflife/elasticsearch", m.DefaultResolver)
	}
}
