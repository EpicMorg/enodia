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

func pageServer(t *testing.T, wantPath string, status int, body []byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wantPath {
			t.Errorf("got path %q, want %q", r.URL.Path, wantPath)
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// netbox_4.3.3_login.html is the head of a production netbox-docker
// instance's /login/, its container hostname replaced.
func TestNetBoxProbeRealFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "netbox_4.3.3_login.html"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	obs, err := netboxProbe{}.Probe(context.Background(), target(pageServer(t, "/login/", 200, raw), "netbox"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "4.3.3" || obs.Extra["netboxDocker"] != "3.3.0" {
		t.Fatalf("got %q %+v", obs.Version, obs.Extra)
	}
}

func TestNetBoxProbeAssetFallbackAndMissing(t *testing.T) {
	obs, err := netboxProbe{}.Probe(context.Background(), target(pageServer(t, "/login/", 200, []byte(`<script src="/static/netbox.js?v=3.7.8"></script>`)), "netbox"))
	if err != nil || obs.Version != "3.7.8" {
		t.Fatalf("got %q, %v", obs.Version, err)
	}
	_, err = netboxProbe{}.Probe(context.Background(), target(pageServer(t, "/login/", 200, []byte("<html></html>")), "netbox"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

// greenbone_gsad_24.12.0_gmp.xml is a production gsad's 401 to /gmp,
// verbatim.
func TestGreenboneProbeRealFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "greenbone_gsad_24.12.0_gmp.xml"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	obs, err := greenboneProbe{}.Probe(context.Background(), target(pageServer(t, "/gmp", http.StatusUnauthorized, raw), "greenbone"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "24.12.0" {
		t.Fatalf("got %q", obs.Version)
	}
}

func TestGreenboneProbeNotGreenbone(t *testing.T) {
	_, err := greenboneProbe{}.Probe(context.Background(), target(pageServer(t, "/gmp", 200, []byte("<!doctype html><html></html>")), "greenbone"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestGreenboneProbeAliases(t *testing.T) {
	for _, name := range []string{"greenbone", "openvas", "gsad"} {
		if p, err := Get(name); err != nil || p.Meta().Product != "greenbone" {
			t.Errorf("%s: %v", name, err)
		}
	}
}
