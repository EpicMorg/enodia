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

func TestGithubTagsSourcePicksHighestVersionNotFirstEntry(t *testing.T) {
	fixture, err := os.ReadFile("testdata/github-tags.sample.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/owner/repo/tags" {
			t.Errorf("got path %q, want /repos/owner/repo/tags", r.URL.Path)
		}
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	src := &githubTagsSource{BaseURL: srv.URL, Client: srv.Client()}
	cycles, err := src.Fetch(context.Background(), probe.ResolverRef{Type: "github-tags", ID: "owner/repo"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(cycles) != 1 {
		t.Fatalf("got %d cycles, want exactly 1", len(cycles))
	}
	c := cycles[0]
	// The fixture lists REL-9_5 between REL-9_17 and REL-9_16 — a naive
	// "first entry wins" (as githubSource does for Releases) would get this
	// wrong, since the tags endpoint documents no reliable ordering.
	if c.Latest != "9.17" {
		t.Fatalf("got latest %q, want 9.17 (must compare parsed versions, not trust list order)", c.Latest)
	}
	if c.Cycle != "9.17" {
		t.Fatalf("got cycle %q, want 9.17", c.Cycle)
	}
	// The tags endpoint carries no dates or lifecycle opinion at all.
	if c.ReleaseDate != nil || c.EOL != nil || c.Support != nil || c.LTS != nil {
		t.Fatalf("got %+v, want ReleaseDate/EOL/Support/LTS all nil (tags endpoint has none of these)", c)
	}
}

func TestGithubTagsSourceSkipsTagsWithNoDigits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"name":"docs-snapshot"},{"name":"nightly"}]`))
	}))
	defer srv.Close()

	src := &githubTagsSource{BaseURL: srv.URL, Client: srv.Client()}
	_, err := src.Fetch(context.Background(), probe.ResolverRef{Type: "github-tags", ID: "owner/repo"})
	if !errors.Is(err, ErrUnknownProduct) {
		t.Fatalf("got %v, want ErrUnknownProduct", err)
	}
}

func TestGithubTagsSource404IsUnknownProduct(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	src := &githubTagsSource{BaseURL: srv.URL, Client: srv.Client()}
	_, err := src.Fetch(context.Background(), probe.ResolverRef{Type: "github-tags", ID: "no/such-repo"})
	if !errors.Is(err, ErrUnknownProduct) {
		t.Fatalf("got %v, want ErrUnknownProduct", err)
	}
}

func TestGithubTagsSourceSendsAuthorizationHeaderWhenTokenSet(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	src := &githubTagsSource{BaseURL: srv.URL, Client: srv.Client(), Token: "s3cret"}
	_, _ = src.Fetch(context.Background(), probe.ResolverRef{Type: "github-tags", ID: "owner/repo"})
	if gotAuth != "Bearer s3cret" {
		t.Fatalf("got Authorization %q, want %q", gotAuth, "Bearer s3cret")
	}
}

func TestNormalizeRELTag(t *testing.T) {
	cases := []struct {
		tag    string
		want   string
		wantOK bool
	}{
		{"REL-9_17", "9.17", true},
		{"REL-2_0", "2.0", true},
		{"REL-10_1", "10.1", true},
		{"docs-snapshot", "", false},
		{"nightly", "", false},
	}
	for _, tc := range cases {
		got, ok := normalizeRELTag(tc.tag)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("normalizeRELTag(%q) = (%q, %v), want (%q, %v)", tc.tag, got, ok, tc.want, tc.wantOK)
		}
	}
}
