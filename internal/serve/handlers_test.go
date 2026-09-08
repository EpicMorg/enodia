// SPDX-License-Identifier: AGPL-3.0-or-later

package serve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleHealthzNeverNeedsASnapshot(t *testing.T) {
	st := &store{} // no Store() call — deliberately empty
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	newMux(st).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ok") {
		t.Fatalf("got %q", rec.Body.String())
	}
}

func TestHandlersReturn503BeforeAnySnapshot(t *testing.T) {
	st := &store{}
	for _, path := range []string{"/", "/report.json", "/metrics"} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		newMux(st).ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: got %d, want 503", path, rec.Code)
		}
	}
}

func TestHandleIndexServesHTML(t *testing.T) {
	st := &store{}
	st.Store(sampleReport("idx"))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	newMux(st).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("got Content-Type %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "<!doctype html>") {
		t.Fatalf("got %q", rec.Body.String())
	}
}

func TestHandleIndexOnlyMatchesRoot(t *testing.T) {
	st := &store{}
	st.Store(sampleReport("idx"))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/nonexistent", nil)
	rec := httptest.NewRecorder()
	newMux(st).ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", rec.Code)
	}
}

func TestHandleJSONServesTheStoredReport(t *testing.T) {
	st := &store{}
	st.Store(sampleReport("json-target"))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/report.json", nil)
	rec := httptest.NewRecorder()
	newMux(st).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("got Content-Type %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "json-target") {
		t.Fatalf("got %q", rec.Body.String())
	}
}

func TestHandleMetricsServesPrometheusFormat(t *testing.T) {
	st := &store{}
	st.Store(sampleReport("metrics-target"))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	newMux(st).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("got Content-Type %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "enodia_target_info") {
		t.Fatalf("got %q", rec.Body.String())
	}
}
