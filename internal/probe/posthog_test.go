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

// posthog_55babe9554_login.html is a production self-hosted PostHog's
// /login, POSTHOG_APP_CONTEXT reduced to a few keys in its real encoding.
func TestPostHogProbeRealFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "posthog_55babe9554_login.html"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" {
			t.Errorf("got path %q", r.URL.Path)
		}
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	obs, err := posthogProbe{}.Probe(context.Background(), target(srv.URL, "posthog"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "55babe9554" || obs.Extra["realm"] != "hosted-clickhouse" {
		t.Fatalf("got %q %+v", obs.Version, obs.Extra)
	}
}

func TestPostHogProbeNotPostHog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>login</html>"))
	}))
	defer srv.Close()
	if _, err := (posthogProbe{}).Probe(context.Background(), target(srv.URL, "posthog")); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}
