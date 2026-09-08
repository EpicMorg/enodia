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

func loadLogstashFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "logstash_8.15.0.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// logstash_8.15.0.json is a real "/" reply captured from a live
// docker.elastic.co/logstash/logstash container's monitoring API, with no
// credentials at all (container hostname/IDs scrubbed).
func TestLogstashProbeParsesRealFixture(t *testing.T) {
	fixture := loadLogstashFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			t.Errorf("got path %q, want /", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := logstashProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "logstash"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "8.15.0" {
		t.Fatalf("got version %q", obs.Version)
	}
}

func TestLogstashProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := logstashProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "logstash"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestLogstashProbeMissingVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"host":"x","status":"green"}`))
	}))
	defer srv.Close()

	p := logstashProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "logstash"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestLogstashProbeMeta(t *testing.T) {
	m := logstashProbe{}.Meta()
	if m.Product != "logstash" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("the monitoring API has no built-in auth at all")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "logstash" {
		t.Fatalf("got resolver %+v, want endoflife/logstash", m.DefaultResolver)
	}
}
