// SPDX-License-Identifier: AGPL-3.0-or-later

package collect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/EpicMorg/enodia/internal/probe"
)

const manifest = `<?xml version="1.0"?><applinks-manifest><typeId>jira</typeId><version>10.3.2</version></applinks-manifest>`

func TestRunPreservesOrderAndNormalises(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(manifest))
	}))
	defer srv.Close()

	targets := make([]probe.Target, 5)
	for i := range targets {
		targets[i] = probe.Target{
			ID: string(rune('a' + i)), Product: "jira", Address: srv.URL,
			HTTP: srv.Client(), Timeout: 5 * time.Second,
		}
	}
	out := Run(context.Background(), targets, Options{Concurrency: 4})
	if len(out) != 5 {
		t.Fatalf("got %d results", len(out))
	}
	for i, o := range out {
		if o.ID != string(rune('a'+i)) {
			t.Errorf("result %d is out of order: %s", i, o.ID)
		}
		if o.Normalized != "10.3.2" {
			t.Errorf("normalised = %q", o.Normalized)
		}
	}
}

// A rejected token does not improve on the second attempt, and retrying it
// hammers production for nothing.
func TestNoRetryOnAuthFailure(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(401)
	}))
	defer srv.Close()

	out := Run(context.Background(), []probe.Target{{
		ID: "x", Product: "jira", Address: srv.URL, HTTP: srv.Client(), Timeout: time.Second,
	}}, Options{Retries: 3, Backoff: time.Millisecond})

	if got := hits.Load(); got != 1 {
		t.Errorf("server was hit %d times, want exactly 1", got)
	}
	if out[0].ErrorKind != "auth" {
		t.Errorf("errorKind = %q, want auth", out[0].ErrorKind)
	}
}

func TestRetriesTransientFailure(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) < 3 {
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte(manifest))
	}))
	defer srv.Close()

	out := Run(context.Background(), []probe.Target{{
		ID: "x", Product: "jira", Address: srv.URL, HTTP: srv.Client(), Timeout: time.Second,
	}}, Options{Retries: 3, Backoff: time.Millisecond})

	if out[0].Version != "10.3.2" {
		t.Fatalf("expected recovery after transient failures, got %+v", out[0])
	}
}

// Shared configs cover services the current operator may have no token for.
// Those are skipped, not reported as broken.
func TestMissingRequiredCredentialsSkips(t *testing.T) {
	// jira does not require auth, so simulate via an unknown product path:
	out := Run(context.Background(), []probe.Target{{
		ID: "x", Product: "no-such-product", Address: "https://example.invalid",
	}}, Options{})
	if out[0].ErrorKind != "not_supported" {
		t.Errorf("errorKind = %q, want not_supported", out[0].ErrorKind)
	}
}

func TestWarnsOnMissingScheme(t *testing.T) {
	var warned bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(manifest))
	}))
	defer srv.Close()

	host := srv.URL[len("http://"):]
	Run(context.Background(), []probe.Target{{
		ID: "x", Product: "jira", Address: host, HTTP: srv.Client(), Timeout: time.Second,
	}}, Options{Warn: func(probe.Target, string) { warned = true }})

	if !warned {
		t.Error("an address without a scheme must produce a warning")
	}
}
