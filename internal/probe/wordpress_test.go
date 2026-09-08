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

func loadWordPressFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// wordpress_7.1_feed.xml is a real /?feed=rss2 reply captured from a live
// wordpress:latest container (a freshly installed "Test Site", hostnames
// scrubbed) with no credentials at all — feeds are always public.
func TestWordPressProbeParsesFeed(t *testing.T) {
	fixture := loadWordPressFixture(t, "wordpress_7.1_feed.xml")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "feed=rss2" {
			t.Errorf("got query %q, want feed=rss2", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/rss+xml")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := wordpressProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "wordpress"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "7.1" {
		t.Fatalf("got version %q", obs.Version)
	}
}

// wordpress_7.1_meta.html is a real "/" reply from the same instance. This
// exercises the fallback path used when the feed doesn't carry the
// generator line — confirmed by reading wp-includes/default-filters.php
// that the single most common hardening snippet (removing wp_head's own
// wp_generator action) leaves the feed's generator untouched, so in
// practice a site that has actually stripped the feed one has usually
// stripped this one too; the fallback exists for the sites that haven't
// stripped either but happen to have feeds disabled entirely.
func TestWordPressProbeFallsBackToHomepageMeta(t *testing.T) {
	fixture := loadWordPressFixture(t, "wordpress_7.1_meta.html")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery == "feed=rss2" {
			w.WriteHeader(http.StatusNotFound) // feeds disabled
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := wordpressProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "wordpress"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "7.1" {
		t.Fatalf("got version %q", obs.Version)
	}
}

func TestWordPressProbeBothStrippedIsNotSupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>not wordpress at all</body></html>"))
	}))
	defer srv.Close()

	p := wordpressProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "wordpress"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestWordPressProbeMeta(t *testing.T) {
	m := wordpressProbe{}.Meta()
	if m.Product != "wordpress" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("both the feed and the homepage are always public")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "wordpress" {
		t.Fatalf("got resolver %+v, want endoflife/wordpress", m.DefaultResolver)
	}
}
