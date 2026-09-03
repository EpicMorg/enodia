// SPDX-License-Identifier: AGPL-3.0-or-later

package resolver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/EpicMorg/enodia/internal/probe"
)

func TestEndoflifeSourceFetchesFixture(t *testing.T) {
	fixture, err := os.ReadFile("testdata/jira-software.sample.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jira-software.json" {
			t.Errorf("got path %q, want /jira-software.json", r.URL.Path)
		}
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	src := &endoflifeSource{BaseURL: srv.URL, Client: srv.Client()}
	cycles, err := src.Fetch(context.Background(), probe.ResolverRef{Type: "endoflife", ID: "jira-software"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(cycles) != 4 {
		t.Fatalf("got %d cycles, want 4", len(cycles))
	}
}

func TestEndoflifeSource404IsUnknownProduct(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	src := &endoflifeSource{BaseURL: srv.URL, Client: srv.Client()}
	_, err := src.Fetch(context.Background(), probe.ResolverRef{Type: "endoflife", ID: "no-such-product"})
	if !errors.Is(err, ErrUnknownProduct) {
		t.Fatalf("got %v, want ErrUnknownProduct", err)
	}
}

func TestEndoflifeSourceServerErrorIsUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	src := &endoflifeSource{BaseURL: srv.URL, Client: srv.Client()}
	_, err := src.Fetch(context.Background(), probe.ResolverRef{Type: "endoflife", ID: "jira-software"})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}
}

func TestEndoflifeSourceMalformedBodyIsUnparseable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	src := &endoflifeSource{BaseURL: srv.URL, Client: srv.Client()}
	_, err := src.Fetch(context.Background(), probe.ResolverRef{Type: "endoflife", ID: "jira-software"})
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestEndoflifeSourceRespectsContextCancellation(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-block
	}))
	defer func() {
		close(block)
		srv.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	src := &endoflifeSource{BaseURL: srv.URL, Client: srv.Client()}
	_, err := src.Fetch(ctx, probe.ResolverRef{Type: "endoflife", ID: "jira-software"})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable (from context deadline)", err)
	}
}
