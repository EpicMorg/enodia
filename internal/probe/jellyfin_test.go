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

func loadJellyfinFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "jellyfin_10.11.11.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// jellyfin_10.11.11.json is a trimmed version of a real
// /System/Info/Public reply captured from a live production instance, with
// its ServerName and persistent install Id replaced by placeholders.
func TestJellyfinProbeParsesRealFixture(t *testing.T) {
	fixture := loadJellyfinFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/System/Info/Public" {
			t.Errorf("got path %q, want /System/Info/Public", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := jellyfinProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "jellyfin"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "10.11.11" {
		t.Fatalf("got version %q", obs.Version)
	}
}

func TestJellyfinProbeWrongProductNameIsErrNotSupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Version":"10.11.11","ProductName":"Emby Server"}`))
	}))
	defer srv.Close()

	p := jellyfinProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "jellyfin"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestJellyfinProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := jellyfinProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "jellyfin"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestJellyfinProbeMissingVersionField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ProductName":"Jellyfin Server"}`))
	}))
	defer srv.Close()

	p := jellyfinProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "jellyfin"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

// This probe must never surface instance-identifying fields (ServerName,
// Id, LocalAddress), even if a server sends them.
func TestJellyfinProbeNeverExposesInstanceIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Version":"10.11.11","ProductName":"Jellyfin Server","ServerName":"S3D","Id":"e9a58f0d3b5a42d2988fc67a839eef43","LocalAddress":"http://127.0.0.1:8096"}`))
	}))
	defer srv.Close()

	p := jellyfinProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "jellyfin"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	for k, v := range obs.Extra {
		if k == "serverName" || k == "id" || k == "localAddress" {
			t.Fatalf("got Extra[%q] = %q, want instance-identifying fields never exposed", k, v)
		}
	}
}

func TestJellyfinProbeMeta(t *testing.T) {
	m := jellyfinProbe{}.Meta()
	if m.Product != "jellyfin" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("this endpoint is intentionally public, confirmed live")
	}
	if len(m.Auth.Kinds) != 0 {
		t.Fatalf("got Kinds %+v, want none: no credentialed path was ever tested", m.Auth.Kinds)
	}
	if m.DefaultResolver.Type != "" {
		t.Fatalf("got resolver %+v, want none (endoflife.date has no jellyfin calendar)", m.DefaultResolver)
	}
}
