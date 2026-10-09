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

func weblateServer(t *testing.T, body []byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/about/" {
			t.Errorf("got path %q, want /about/", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// weblate_2026.10_about.html is /about/ from a live weblate/weblate:latest
// container, its CSRF token blanked.
func TestWeblateProbeRealFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "weblate_2026.10_about.html"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	obs, err := weblateProbe{}.Probe(context.Background(), target(weblateServer(t, raw), "weblate"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "2026.10" {
		t.Fatalf("got %q", obs.Version)
	}
}

// A 5.x footer, and a page whose footer is customised away but still
// links its versioned documentation.
func TestWeblateProbeOtherShapes(t *testing.T) {
	for body, want := range map[string]string{
		`<footer>Powered by <a href="https://weblate.org/">Weblate 5.10.4</a></footer>`:                    "5.10.4",
		`<a class="dropdown-item" href="https://docs.weblate.org/en/weblate-2026.9.1/index.html">Docs</a>`: "2026.9.1",
	} {
		obs, err := weblateProbe{}.Probe(context.Background(), target(weblateServer(t, []byte(body)), "weblate"))
		if err != nil || obs.Version != want {
			t.Errorf("%q: got %q, %v; want %q", body, obs.Version, err, want)
		}
	}
}

func TestWeblateProbeNotWeblate(t *testing.T) {
	_, err := weblateProbe{}.Probe(context.Background(), target(weblateServer(t, []byte("<html>hello</html>")), "weblate"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestWeblateProbeMeta(t *testing.T) {
	m := weblateProbe{}.Meta()
	if m.Product != "weblate" || m.Auth.Required || m.DefaultResolver != (ResolverRef{Type: "github", ID: "WeblateOrg/weblate"}) {
		t.Fatalf("got %+v", m)
	}
}
