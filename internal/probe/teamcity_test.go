// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// teamcityAuthedTarget carries a token, which is what sends the probe to
// /app/rest/server rather than the anonymous /app/rest/server/version.
func teamcityAuthedTarget(addr string) Target {
	tt := target(addr, "teamcity")
	tt.Creds = Credentials{Kind: AuthBearer, Value: "token"}
	tt.AllowInsecureTransport = true // httptest is plain HTTP
	return tt
}

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
	obs, err := p.Probe(context.Background(), teamcityAuthedTarget(srv.URL))
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
	// A fresh TeamCity install answers /app/rest/server exactly this way:
	// 401 with both Basic and Bearer challenges — confirmed live, not
	// assumed. With a token configured that is a real auth failure.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="TeamCity"`)
		w.Header().Add("WWW-Authenticate", `Bearer realm="TeamCity"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := teamcityProbe{}
	_, err := p.Probe(context.Background(), teamcityAuthedTarget(srv.URL))
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
	_, err := p.Probe(context.Background(), teamcityAuthedTarget(srv.URL))
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
	_, err := p.Probe(context.Background(), teamcityAuthedTarget(srv.URL))
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

// The reply /app/rest/server/version gave anonymously on fresh 2017.2.4
// through 2026.1.1 containers: plain text, no trailing newline.
func TestTeamCityProbeAnonymousVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/rest/server/version" {
			t.Errorf("got path %q, want /app/rest/server/version", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("anonymous request sent Authorization %q", got)
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("2026.1.1 (build 222577)"))
	}))
	defer srv.Close()

	obs, err := teamcityProbe{}.Probe(context.Background(), target(srv.URL, "teamcity"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "2026.1.1 (build 222577)" || obs.Extra["buildNumber"] != "222577" {
		t.Fatalf("got version %q extra %+v", obs.Version, obs.Extra)
	}
	if obs.Endpoint != "/app/rest/server/version" {
		t.Fatalf("got endpoint %q", obs.Endpoint)
	}
}

func TestTeamCityProbeAnonymousOlderVersionShapes(t *testing.T) {
	for _, reply := range []string{"2024.03 (build 156166)", "2017.2.4 (build 51228)\n"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(reply))
		}))
		obs, err := teamcityProbe{}.Probe(context.Background(), target(srv.URL, "teamcity"))
		srv.Close()
		if err != nil {
			t.Fatalf("%q: Probe: %v", reply, err)
		}
		if want := strings.TrimSpace(reply); obs.Version != want {
			t.Fatalf("got %q, want %q", obs.Version, want)
		}
	}
}

// While TeamCity starts up it answers every path, this one included, with
// an HTML maintenance page — seen live on each fresh container.
func TestTeamCityProbeAnonymousStartupPageIsUnparseable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!-- Page: maintenance-welcome Stage: APPLICATION_STARTING -->\n<html>build 222577</html>"))
	}))
	defer srv.Close()

	_, err := teamcityProbe{}.Probe(context.Background(), target(srv.URL, "teamcity"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}
