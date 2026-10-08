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

// ghost_6.69_site.json is a live ghost:6 container's anonymous
// /ghost/api/admin/site/ reply, site_uuid zeroed.
func TestGhostProbeRealFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "ghost_6.69_site.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ghost/api/admin/site/" {
			t.Errorf("got path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	obs, err := ghostProbe{}.Probe(context.Background(), target(srv.URL, "ghost"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "6.69" {
		t.Fatalf("got %q", obs.Version)
	}
}

func TestGhostProbeNotGhost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>not ghost</html>"))
	}))
	defer srv.Close()
	if _, err := (ghostProbe{}).Probe(context.Background(), target(srv.URL, "ghost")); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestGhostProbeMeta(t *testing.T) {
	m := ghostProbe{}.Meta()
	if m.Product != "ghost" || m.Auth.Required || m.DefaultResolver != (ResolverRef{Type: "github", ID: "TryGhost/Ghost"}) {
		t.Fatalf("got %+v", m)
	}
}
