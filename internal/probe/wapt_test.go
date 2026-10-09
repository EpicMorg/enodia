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

func waptServer(t *testing.T, body []byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ping" {
			t.Errorf("got path %q", r.URL.Path)
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// wapt_1.8.2_ping.json is a production WAPT 1.8.2 server's anonymous
// /ping, its uuid zeroed and date fixed.
func TestWAPTProbeRealFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "wapt_1.8.2_ping.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	obs, err := waptProbe{}.Probe(context.Background(), target(waptServer(t, raw), "wapt"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "1.8.2.7334" || obs.Extra["edition"] != "community" || obs.Extra["apiVersion"] != "v3" {
		t.Fatalf("got %q %+v", obs.Version, obs.Extra)
	}
}

func TestWAPTProbeVersionWithoutBuild(t *testing.T) {
	obs, err := waptProbe{}.Probe(context.Background(), target(waptServer(t, []byte(`{"result":{"version":"2.6.0","git_hash":"2d15afd9"}}`)), "wapt"))
	if err != nil || obs.Version != "2.6.0" {
		t.Fatalf("got %q, %v", obs.Version, err)
	}
}

func TestWAPTProbeNotWAPT(t *testing.T) {
	if _, err := (waptProbe{}).Probe(context.Background(), target(waptServer(t, []byte("pong")), "wapt")); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}
