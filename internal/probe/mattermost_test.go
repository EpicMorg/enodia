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

func loadMattermostFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "mattermost_11.7.2.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// mattermost_11.7.2.json is a trimmed version of a real
// /api/v4/config/client?format=old reply captured from a live production
// instance. The real response has a hundred-plus keys, several of them
// genuinely identifying that specific deployment (SiteName, SupportEmail,
// a telemetry ID, an asymmetric signing key) — none of that is reproduced
// here since none of it is read by the probe.
func TestMattermostProbeParsesRealFixture(t *testing.T) {
	fixture := loadMattermostFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/config/client" {
			t.Errorf("got path %q, want /api/v4/config/client", r.URL.Path)
		}
		if r.URL.RawQuery != "format=old" {
			t.Errorf("got query %q, want format=old", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := mattermostProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "mattermost"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "11.7.2" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["buildNumber"] != "26431767452" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
	if obs.Extra["buildHash"] != "70c68d0cf6357e2b5c6b66bcc6ffc03bd13d1910" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

// This probe must never surface instance-identifying fields, even if a
// server sends them — guards against a future field-widening mistake
// leaking a real deployment's site name, support email or telemetry/
// diagnostic IDs into stored inventory data.
func TestMattermostProbeNeverExposesInstanceIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"Version": "11.7.2",
			"SiteName": "Saber Mattermost",
			"SupportEmail": "noreply@saber.games",
			"DiagnosticId": "ue9rabdqnt8imxo9jrnx1dktye",
			"TelemetryId": "ue9rabdqnt8imxo9jrnx1dktye",
			"AsymmetricSigningPublicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."
		}`))
	}))
	defer srv.Close()

	p := mattermostProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "mattermost"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	for k, v := range obs.Extra {
		if k == "siteName" || k == "supportEmail" || k == "diagnosticId" || k == "telemetryId" || k == "asymmetricSigningPublicKey" {
			t.Fatalf("got Extra[%q] = %q, want instance-identifying fields never exposed", k, v)
		}
	}
}

func TestMattermostProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := mattermostProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "mattermost"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestMattermostProbeMissingVersionField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"BuildNumber":"26431767452"}`))
	}))
	defer srv.Close()

	p := mattermostProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "mattermost"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestMattermostProbeMeta(t *testing.T) {
	m := mattermostProbe{}.Meta()
	if m.Product != "mattermost" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("this endpoint is intentionally public, confirmed live: a login page needs it before any session exists")
	}
	if len(m.Auth.Kinds) != 0 {
		t.Fatalf("got Kinds %+v, want none: no credentialed path was ever tested", m.Auth.Kinds)
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "mattermost" {
		t.Fatalf("got resolver %+v, want endoflife/mattermost", m.DefaultResolver)
	}
}
