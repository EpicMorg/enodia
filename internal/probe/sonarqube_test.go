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

func loadSonarQubeFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "sonarqube_9.9.8.100196.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// sonarqube_9.9.8.100196.json is a real /api/system/status reply captured
// from a live sonarqube:lts-community container, with the random per-install
// "id" replaced by a fixed placeholder — the parser only reads
// version/status, and id is just echoed back, not validated.
func TestSonarQubeProbeParsesRealFixture(t *testing.T) {
	fixture := loadSonarQubeFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/system/status" {
			t.Errorf("got path %q, want /api/system/status", r.URL.Path)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("got Accept %q, want application/json", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := sonarqubeProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "sonarqube"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "9.9.8.100196" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["status"] != "UP" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
	if obs.Extra["id"] == "" {
		t.Fatalf("got extra %+v, want a non-empty id", obs.Extra)
	}
}

// A degraded server (e.g. mid-startup) still answers with its version — the
// status field records that fact, but a non-UP status is not this probe's
// call to turn into an error (D7).
func TestSonarQubeProbeNonUPStatusIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"x","version":"9.9.8.100196","status":"STARTING"}`))
	}))
	defer srv.Close()

	p := sonarqubeProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "sonarqube"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Extra["status"] != "STARTING" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

func TestSonarQubeProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := sonarqubeProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "sonarqube"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestSonarQubeProbeMissingVersionField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"x","status":"UP"}`))
	}))
	defer srv.Close()

	p := sonarqubeProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "sonarqube"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestSonarQubeProbeMeta(t *testing.T) {
	m := sonarqubeProbe{}.Meta()
	if m.Product != "sonarqube" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("this endpoint stays public even with forceAuthentication enabled, confirmed live")
	}
	if len(m.Auth.Kinds) != 0 {
		t.Fatalf("got Kinds %+v, want none: no credentialed path was ever tested", m.Auth.Kinds)
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "sonarqube-community" {
		t.Fatalf("got resolver %+v, want endoflife/sonarqube-community", m.DefaultResolver)
	}
}
