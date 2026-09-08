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

func loadArtifactoryFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "artifactory_7.161.20.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// artifactory_7.161.20.json is a real /artifactory/api/system/version reply
// captured from a live releases-docker.jfrog.io/jfrog/artifactory-oss
// container (authenticated with its default admin account). The parser
// deliberately ignores everything but version/revision — see the license
// note on artifactoryProbe for why.
func TestArtifactoryProbeParsesRealFixture(t *testing.T) {
	fixture := loadArtifactoryFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/artifactory/api/system/version" {
			t.Errorf("got path %q, want /artifactory/api/system/version", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := artifactoryProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "artifactory"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "7.161.20" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["revision"] != "86120900" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

// A production instance was confirmed live to answer this endpoint with no
// credentials at all ("Allow Anonymous Access" enabled) — this probe must
// not assume the fresh-install default (401) is the only real behavior.
func TestArtifactoryProbeAnonymousSuccessIsSupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":"7.117.12","revision":"81712900"}`))
	}))
	defer srv.Close()

	p := artifactoryProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "artifactory"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "7.117.12" {
		t.Fatalf("got version %q", obs.Version)
	}
}

func TestArtifactoryProbeUnauthorizedIsErrAuth(t *testing.T) {
	// A fresh install answers exactly this way: 401 with a Basic challenge,
	// confirmed live, not assumed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Artifactory Realm"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := artifactoryProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "artifactory"))
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestArtifactoryProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := artifactoryProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "artifactory"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestArtifactoryProbeMissingVersionField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"revision":"86120900"}`))
	}))
	defer srv.Close()

	p := artifactoryProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "artifactory"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

// This probe must never surface license, addons or entitlements, even if a
// server sends them — that guards against a future field-widening mistake
// leaking a real per-install license fingerprint into stored inventory data.
func TestArtifactoryProbeNeverExposesLicenseInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":"7.117.12","revision":"81712900","license":"d9022995838bd49d9eb50b6e405005b6c8f40de94","addons":["xray"],"entitlements":{"REPO_REPLICATION":true}}`))
	}))
	defer srv.Close()

	p := artifactoryProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "artifactory"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	for k, v := range obs.Extra {
		if k == "license" || k == "addons" || k == "entitlements" {
			t.Fatalf("got Extra[%q] = %q, want license-related fields never exposed", k, v)
		}
	}
}

func TestArtifactoryProbeMeta(t *testing.T) {
	m := artifactoryProbe{}.Meta()
	if m.Product != "artifactory" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("a real production instance answered anonymously, confirmed live: credentials are not always required")
	}
	if !m.Auth.Accepts(AuthBasic) {
		t.Fatal("expected AuthBasic to be accepted")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "artifactory" {
		t.Fatalf("got resolver %+v, want endoflife/artifactory", m.DefaultResolver)
	}
}
