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

func loadGitLabFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "gitlab_19.3.1.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// gitlab_19.3.1.json is a real /api/v4/version reply captured from a live
// gitlab/gitlab-ce container (authenticated with a personal access token
// created via `gitlab-rails runner`), with the container-hostname-derived
// kas URLs replaced by a fixed placeholder host — the parser only reads
// version/revision/enterprise, and kas is not inspected.
func TestGitLabProbeParsesRealFixture(t *testing.T) {
	fixture := loadGitLabFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/version" {
			t.Errorf("got path %q, want /api/v4/version", r.URL.Path)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("got Accept %q, want application/json", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := gitlabProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "gitlab"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "19.3.1" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["revision"] != "668508315ee" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
	if obs.Extra["enterprise"] != "false" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

func TestGitLabProbeUnauthorizedIsErrAuth(t *testing.T) {
	// A fresh GitLab instance answers exactly this way: 401 with a JSON
	// body, confirmed live against a real gitlab/gitlab-ce container that
	// had not been given a PRIVATE-TOKEN.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"401 Unauthorized"}`))
	}))
	defer srv.Close()

	p := gitlabProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "gitlab"))
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestGitLabProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := gitlabProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "gitlab"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestGitLabProbeMissingVersionField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"revision":"668508315ee"}`))
	}))
	defer srv.Close()

	p := gitlabProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "gitlab"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestGitLabProbeMeta(t *testing.T) {
	m := gitlabProbe{}.Meta()
	if m.Product != "gitlab" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("credentials are not always required: some deployments may relax this endpoint")
	}
	if !m.Auth.Accepts(AuthTokenHeader) {
		t.Fatal("expected AuthTokenHeader (PRIVATE-TOKEN) to be accepted")
	}
	if !m.Auth.Accepts(AuthBearer) {
		t.Fatal("Bearer was tried live against a personal access token and accepted")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "gitlab" {
		t.Fatalf("got resolver %+v, want endoflife/gitlab", m.DefaultResolver)
	}
}
