// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/EpicMorg/enodia/internal/probe"
)

func TestResolveSchemeHTTPSSucceeds(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	scheme, err := resolveScheme(context.Background(), addr, probe.TLSSettings{Insecure: true}, time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scheme != "https" {
		t.Fatalf("got %q, want https", scheme)
	}
}

func TestResolveSchemeAnyStatusCodeCounts(t *testing.T) {
	// A 404 still proves the scheme/transport works — resolveScheme is
	// deciding transport, not whether a particular path exists.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	scheme, err := resolveScheme(context.Background(), addr, probe.TLSSettings{Insecure: true}, time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scheme != "https" {
		t.Fatalf("got %q, want https", scheme)
	}
}

func TestResolveSchemeFallsBackToHTTP(t *testing.T) {
	// Nothing listens on TLS at this address, so the https attempt must
	// fail and fall back to plain http — never the other way around (D12).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	scheme, err := resolveScheme(context.Background(), addr, probe.TLSSettings{}, time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scheme != "http" {
		t.Fatalf("got %q, want http", scheme)
	}
}

func TestResolveSchemeBothFail(t *testing.T) {
	_, err := resolveScheme(context.Background(), "127.0.0.1:1", probe.TLSSettings{}, 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected an error when nothing listens on either scheme")
	}
}

func TestResolveSchemeHonoursTLSSettings(t *testing.T) {
	// Without Insecure, the self-signed test certificate must be rejected,
	// so the result must never be reported as a trusted "https". (The http
	// fallback attempt against the same port may or may not itself succeed —
	// Go's TLS listener answers a plaintext HTTP request with a plaintext
	// error the client can parse as a response — so that part isn't asserted
	// here; see TestResolveSchemeFallsBackToHTTP for the real fallback case.)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	scheme, _ := resolveScheme(context.Background(), addr, probe.TLSSettings{}, 500*time.Millisecond)
	if scheme == "https" {
		t.Fatal("the untrusted self-signed certificate must not be accepted as https")
	}
}
