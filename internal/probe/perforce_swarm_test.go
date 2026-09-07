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

func loadPerforceSwarmFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "perforce_swarm_2024.6.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// perforce_swarm_2024.6.json is a real /api/version reply, identical across
// several live production instances checked directly.
func TestPerforceSwarmProbeParsesRealFixture(t *testing.T) {
	fixture := loadPerforceSwarmFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/version" {
			t.Errorf("got path %q, want /api/version", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := perforceSwarmProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "perforce-swarm"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "2024.6" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["changelist"] != "2710109" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
	if obs.Extra["releaseDate"] != "2025/01/28" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
	if obs.Extra["raw"] != "SWARM/2024.6/2710109 (2025/01/28)" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

// An out-of-range API version number was confirmed live to answer 401 on an
// otherwise fully anonymous endpoint — this probe avoids that entirely by
// using the unversioned path, but if a server ever does demand auth, that
// must still surface as ErrAuth rather than being swallowed.
func TestPerforceSwarmProbeUnauthorizedIsErrAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := perforceSwarmProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "perforce-swarm"))
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestPerforceSwarmProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := perforceSwarmProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "perforce-swarm"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestPerforceSwarmProbeMissingVersionField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"apiVersions":[9,10,11],"year":"2024"}`))
	}))
	defer srv.Close()

	p := perforceSwarmProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "perforce-swarm"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

// A version string that does not match the expected "SWARM/x/y (z)" shape
// must not fail the probe outright — the server still reported something
// real, just not in the shape this probe knows how to split up.
func TestPerforceSwarmProbeUnrecognizedVersionFormatIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"apiVersions":[11],"version":"something-unexpected","year":"2030"}`))
	}))
	defer srv.Close()

	p := perforceSwarmProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "perforce-swarm"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "something-unexpected" {
		t.Fatalf("got version %q", obs.Version)
	}
}

func TestPerforceSwarmProbeMeta(t *testing.T) {
	m := perforceSwarmProbe{}.Meta()
	if m.Product != "perforce-swarm" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("this endpoint is intentionally public, confirmed live")
	}
	if len(m.Auth.Kinds) != 0 {
		t.Fatalf("got Kinds %+v, want none: no credentialed path was ever tested", m.Auth.Kinds)
	}
	if m.DefaultResolver.Type != "" {
		t.Fatalf("got resolver %+v, want none (endoflife.date has no perforce-swarm calendar)", m.DefaultResolver)
	}
}
