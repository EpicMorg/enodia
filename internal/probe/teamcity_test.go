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

func loadTeamCityFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "teamcity_2026.2.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// teamcity_2026.2.json is a real /app/rest/server reply captured from a
// live jetbrains/teamcity-server container (authenticated with its
// bootstrap superuser token), with the random internalId and this
// container's own startTime/currentTime replaced by fixed placeholders —
// the parser only reads version/buildNumber/internalId, and internalId
// itself is just echoed back, not validated.
func TestTeamCityProbeParsesRealFixture(t *testing.T) {
	fixture := loadTeamCityFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/rest/server" {
			t.Errorf("got path %q, want /app/rest/server", r.URL.Path)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("got Accept %q, want application/json", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := teamcityProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "teamcity"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "2026.2 (build 238924)" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["buildNumber"] != "238924" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

func TestTeamCityProbeUnauthorizedIsErrAuth(t *testing.T) {
	// A fresh TeamCity install answers exactly this way: 401 with both
	// Basic and Bearer challenges, guest access off by default — confirmed
	// live, not assumed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="TeamCity"`)
		w.Header().Add("WWW-Authenticate", `Bearer realm="TeamCity"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := teamcityProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "teamcity"))
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestTeamCityProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := teamcityProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "teamcity"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestTeamCityProbeMissingVersionField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"buildNumber":"238924"}`))
	}))
	defer srv.Close()

	p := teamcityProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "teamcity"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestTeamCityProbeMeta(t *testing.T) {
	m := teamcityProbe{}.Meta()
	if m.Product != "teamcity" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("credentials are not always required: a target might allow guest access")
	}
	if !m.Auth.Accepts(AuthBasic) {
		t.Fatal("expected AuthBasic to be accepted: the bootstrap superuser token needs it")
	}
	if !m.Auth.Accepts(AuthBearer) {
		t.Fatal("expected AuthBearer to be accepted: a real user's access token, confirmed live against production, needs it")
	}
	if m.DefaultResolver.Type != "" {
		t.Fatalf("got resolver %+v, want none (endoflife.date has no teamcity calendar)", m.DefaultResolver)
	}
}
