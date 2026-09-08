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

func loadClickHouseFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "clickhouse_26.8.2.7.txt"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// clickhouse_26.8.2.7.txt is the real, bare TabSeparated reply to
// `SELECT version()` captured from a live clickhouse/clickhouse-server
// container — a single-column, single-row result is just the value and a
// newline, nothing to unmarshal.
func TestClickHouseProbeParsesRealFixture(t *testing.T) {
	fixture := loadClickHouseFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("query"); got != "SELECT version()" {
			t.Errorf("got query %q, want \"SELECT version()\"", got)
		}
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := clickhouseProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "clickhouse"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "26.8.2.7" {
		t.Fatalf("got version %q", obs.Version)
	}
}

// Confirmed live: a recent clickhouse/clickhouse-server image with no
// CLICKHOUSE_PASSWORD configured answers plain 401 to an unauthenticated
// query — already ordinary ErrAuth via FetchHTTP, nothing probe-specific.
func TestClickHouseProbeUnauthorizedIsErrAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Code: 194. DB::Exception: default: Authentication failed"))
	}))
	defer srv.Close()

	p := clickhouseProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "clickhouse"))
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestClickHouseProbeUnrelatedBodyIsUnparseable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>not clickhouse at all</html>"))
	}))
	defer srv.Close()

	p := clickhouseProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "clickhouse"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestClickHouseProbeMeta(t *testing.T) {
	m := clickhouseProbe{}.Meta()
	if m.Product != "clickhouse" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("an install with no password set (older default, or an explicit choice) answers anonymously")
	}
	if !m.Auth.Accepts(AuthBasic) {
		t.Fatal("ClickHouse's HTTP interface takes ordinary HTTP Basic")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "clickhouse" {
		t.Fatalf("got resolver %+v, want endoflife/clickhouse", m.DefaultResolver)
	}
}
