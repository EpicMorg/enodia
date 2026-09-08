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

func loadJenkinsFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// jenkins_2.541.3_header.txt holds the exact "X-Jenkins" header value seen
// on both a 200 and a 403 response from a live jenkins/jenkins:lts-jdk17
// container. jenkins_2.541.3.json is that same container's real /api/json
// body once authenticated (its local urls scrubbed) — the parser only
// reads mode/useSecurity from it.
func TestJenkinsProbeAuthenticatedParsesRealFixture(t *testing.T) {
	version := strings.TrimSpace(string(loadJenkinsFixture(t, "jenkins_2.541.3_header.txt")))
	body := loadJenkinsFixture(t, "jenkins_2.541.3.json")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/json" {
			t.Errorf("got path %q, want /api/json", r.URL.Path)
		}
		w.Header().Set("X-Jenkins", version)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	p := jenkinsProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "jenkins"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "2.541.3" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["mode"] != "NORMAL" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
	if obs.Extra["useSecurity"] != "true" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

// A fresh instance's anonymous-read-denied 403 still carries X-Jenkins —
// confirmed live — so this must not be ErrAuth, and there is no JSON body
// to parse (Jenkins serves an HTML redirect to /login instead).
func TestJenkinsProbeAnonymous403IsNotAnError(t *testing.T) {
	version := strings.TrimSpace(string(loadJenkinsFixture(t, "jenkins_2.541.3_header.txt")))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Jenkins", version)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html>Authentication required</html>"))
	}))
	defer srv.Close()

	p := jenkinsProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "jenkins"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "2.541.3" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra != nil {
		t.Fatalf("got extra %+v, want none: a 403 body is not JSON", obs.Extra)
	}
}

func TestJenkinsProbeMissingHeaderIsErrUnparseable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	p := jenkinsProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "jenkins"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestJenkinsProbeOtherAuthFailureIsErrAuth(t *testing.T) {
	// 401, unlike Jenkins's own anonymous-403, is a real auth failure (e.g.
	// a reverse proxy in front of Jenkins) and must still surface as such.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := jenkinsProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "jenkins"))
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestJenkinsProbeMeta(t *testing.T) {
	m := jenkinsProbe{}.Meta()
	if m.Product != "jenkins" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("credentials are not always required: version is readable from an anonymous 403 too")
	}
	if !m.Auth.Accepts(AuthBasic) {
		t.Fatal("expected AuthBasic to be accepted: Jenkins API tokens are sent as HTTP Basic")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "jenkins" {
		t.Fatalf("got resolver %+v, want endoflife/jenkins", m.DefaultResolver)
	}
}
