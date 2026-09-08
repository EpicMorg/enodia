// SPDX-License-Identifier: AGPL-3.0-or-later

package resolver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/EpicMorg/enodia/internal/probe"
)

func TestGithubSourceSkipsDraftAndPrereleaseAndPicksFirstReal(t *testing.T) {
	fixture, err := os.ReadFile("testdata/github-releases.sample.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/owner/repo/releases" {
			t.Errorf("got path %q, want /repos/owner/repo/releases", r.URL.Path)
		}
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	src := &githubSource{BaseURL: srv.URL, Client: srv.Client()}
	cycles, err := src.Fetch(context.Background(), probe.ResolverRef{Type: "github", ID: "owner/repo"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(cycles) != 1 {
		t.Fatalf("got %d cycles, want exactly 1 (the fallback reports only the latest)", len(cycles))
	}
	c := cycles[0]
	if c.Latest != "v2.9.0" {
		t.Fatalf("got latest %q, want v2.9.0 (must skip the newer draft and prerelease)", c.Latest)
	}
	if c.ReleaseDate == nil {
		t.Fatal("expected a release date from published_at")
	}
	// GitHub has no opinion on lifecycle: these must stay unset, not false.
	if c.EOL != nil || c.Support != nil || c.LTS != nil {
		t.Fatalf("got %+v, want EOL/Support/LTS all nil (unknown, not false)", c)
	}
}

func TestGithubSourceNoEligibleReleaseIsUnknownProduct(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"tag_name":"v1.0.0-rc1","draft":false,"prerelease":true,"published_at":"2026-01-01T00:00:00Z"}]`))
	}))
	defer srv.Close()

	src := &githubSource{BaseURL: srv.URL, Client: srv.Client()}
	_, err := src.Fetch(context.Background(), probe.ResolverRef{Type: "github", ID: "owner/repo"})
	if !errors.Is(err, ErrUnknownProduct) {
		t.Fatalf("got %v, want ErrUnknownProduct", err)
	}
}

func TestGithubSource404IsUnknownProduct(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	src := &githubSource{BaseURL: srv.URL, Client: srv.Client()}
	_, err := src.Fetch(context.Background(), probe.ResolverRef{Type: "github", ID: "no/such-repo"})
	if !errors.Is(err, ErrUnknownProduct) {
		t.Fatalf("got %v, want ErrUnknownProduct", err)
	}
}

func TestGithubSourceSendsAuthorizationHeaderWhenTokenSet(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	src := &githubSource{BaseURL: srv.URL, Client: srv.Client(), Token: "s3cret"}
	_, _ = src.Fetch(context.Background(), probe.ResolverRef{Type: "github", ID: "owner/repo"})
	if gotAuth != "Bearer s3cret" {
		t.Fatalf("got Authorization %q, want %q", gotAuth, "Bearer s3cret")
	}
}
