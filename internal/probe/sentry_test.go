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

// sentry_26.2.1_login.html is the login page of a production self-hosted
// Sentry 26.2.1 reduced to the __initialData keys that matter, values as
// served, its hostname replaced by sentry.example.com.
func TestSentryProbeRealFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "sentry_26.2.1_login.html"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/login/": // the real server redirects to the single org's page
			http.Redirect(w, r, "/auth/login/example-org/", http.StatusFound)
		case "/auth/login/example-org/":
			_, _ = w.Write(raw)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	obs, err := sentryProbe{}.Probe(context.Background(), target(srv.URL, "sentry"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "26.2.1" || obs.Extra["build"] != "7d6777321a7f148a5f7f000900a9b25619193339" || obs.Extra["mode"] != "SELF_HOSTED" {
		t.Fatalf("got %q %+v", obs.Version, obs.Extra)
	}
}

func TestSentryProbeNotSentry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>login</body></html>"))
	}))
	defer srv.Close()
	if _, err := (sentryProbe{}).Probe(context.Background(), target(srv.URL, "sentry")); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestSentryProbeMeta(t *testing.T) {
	m := sentryProbe{}.Meta()
	if m.Product != "sentry" || m.Auth.Required || m.DefaultResolver != (ResolverRef{Type: "github", ID: "getsentry/self-hosted"}) {
		t.Fatalf("got %+v", m)
	}
}
