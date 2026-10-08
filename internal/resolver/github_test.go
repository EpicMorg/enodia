// SPDX-License-Identifier: AGPL-3.0-or-later

package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

// WeblateOrg/weblate tags "weblate-2026.10"; bitwarden/server "v2026.9.1"
// keeps its v for version.Clean to strip.
func TestTrimRepoPrefix(t *testing.T) {
	for _, tc := range []struct{ tag, repo, want string }{
		{"weblate-2026.10", "WeblateOrg/weblate", "2026.10"},
		{"Weblate_5.10.4", "WeblateOrg/weblate", "5.10.4"},
		{"v2026.9.1", "bitwarden/server", "v2026.9.1"},
		{"server-1.0", "bitwarden/server", "1.0"},
		{"weblate", "WeblateOrg/weblate", "weblate"},
		{"weblatex-1.0", "WeblateOrg/weblate", "weblatex-1.0"},
		{"1.2.3", "noslash", "1.2.3"},
	} {
		if got := trimRepoPrefix(tc.tag, tc.repo); got != tc.want {
			t.Errorf("trimRepoPrefix(%q, %q) = %q, want %q", tc.tag, tc.repo, got, tc.want)
		}
	}
}

// minio/minio's real releases list is 3.4MB for 30 entries, every one
// carrying its whole changelog; a 1MiB cap cut it mid-JSON.
func TestGithubSourceReadsLargeReleaseLists(t *testing.T) {
	big := strings.Repeat("x", 200<<10)
	var b strings.Builder
	b.WriteString("[")
	for i := range 30 {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"tag_name":"RELEASE.2025-10-%02dT00-00-00Z","draft":false,"prerelease":false,"body":%q}`, 30-i, big)
	}
	b.WriteString("]")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(b.String()))
	}))
	defer srv.Close()

	src := &githubSource{BaseURL: srv.URL, Client: srv.Client()}
	cycles, err := src.Fetch(context.Background(), probe.ResolverRef{Type: "github", ID: "minio/minio"})
	if err != nil {
		t.Fatalf("Fetch (%d bytes): %v", b.Len(), err)
	}
	if cycles[0].Latest != "RELEASE.2025-10-30T00-00-00Z" {
		t.Fatalf("got %q", cycles[0].Latest)
	}
}
