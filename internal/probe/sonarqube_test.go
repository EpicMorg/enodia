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
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "sonarqube-server" {
		t.Fatalf("got resolver %+v, want endoflife/sonarqube-server", m.DefaultResolver)
	}
}

func TestSonarQubeResolverFor(t *testing.T) {
	cases := []struct {
		version string
		want    ResolverRef
	}{
		// Post-split SonarQube Server: four-digit calendar year.
		{"2025.4.8", ResolverRef{Type: "endoflife", ID: "sonarqube-server"}},
		{"2026.4.1", ResolverRef{Type: "endoflife", ID: "sonarqube-server"}},
		// Post-split Community Build: two-digit calendar year.
		{"24.12.0.100206", ResolverRef{Type: "endoflife", ID: "sonarqube-community"}},
		{"26.9.0.129388", ResolverRef{Type: "endoflife", ID: "sonarqube-community"}},
		// Pre-split bare major versions: identical on both pages.
		{"9.9.8.100196", ResolverRef{Type: "endoflife", ID: "sonarqube-community"}},
		{"10.7.0.96327", ResolverRef{Type: "endoflife", ID: "sonarqube-community"}},
	}
	for _, tc := range cases {
		if got := sonarqubeResolverFor(tc.version); got != tc.want {
			t.Errorf("sonarqubeResolverFor(%q) = %+v, want %+v", tc.version, got, tc.want)
		}
	}
}

// This reply's shape (id/version/status) is real and already captured in
// the Community Build fixture above; only the version string is inlined
// here (2025.4.8 is a real listed cycle on endoflife.date's own
// sonarqube-server page) — no live Server install was available to
// capture a full response from directly.
func TestSonarQubeProbePicksServerResolverForCalendarVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"x","version":"2025.4.8","status":"UP"}`))
	}))
	defer srv.Close()

	p := sonarqubeProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "sonarqube"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	want := ResolverRef{Type: "endoflife", ID: "sonarqube-server"}
	if obs.Resolver != want {
		t.Fatalf("got resolver %+v, want %+v", obs.Resolver, want)
	}
}

func TestSonarQubeProbePicksCommunityResolverForRealFixture(t *testing.T) {
	fixture := loadSonarQubeFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := sonarqubeProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "sonarqube"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	want := ResolverRef{Type: "endoflife", ID: "sonarqube-community"}
	if obs.Resolver != want {
		t.Fatalf("got resolver %+v, want %+v (pre-split version, defaults to community lineage)", obs.Resolver, want)
	}
}
