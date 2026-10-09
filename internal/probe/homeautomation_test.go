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

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// homeassistant_2026.10.0_config.json is a live container's /api/config
// reduced to the keys the probe reads (the rest is location and paths).
func TestHomeAssistantProbe(t *testing.T) {
	raw := readFixture(t, "homeassistant_2026.10.0_config.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/config" {
			t.Errorf("got path %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer llat" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	tt := target(srv.URL, "home-assistant")
	tt.Creds = Credentials{Kind: AuthBearer, Value: "llat"}
	tt.AllowInsecureTransport = true
	obs, err := homeAssistantProbe{}.Probe(context.Background(), tt)
	if err != nil || obs.Version != "2026.10.0" || obs.Extra["state"] != "RUNNING" {
		t.Fatalf("got %q %+v, %v", obs.Version, obs.Extra, err)
	}

	tt.Creds.Value = "wrong" // what the live container answered: 401
	if _, err := (homeAssistantProbe{}).Probe(context.Background(), tt); !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

// openhab_5.2.2_rest.json is a live openhab/openhab:latest's anonymous
// /rest/, links trimmed and its address replaced.
func TestOpenHABProbe(t *testing.T) {
	raw := readFixture(t, "openhab_5.2.2_rest.json")
	obs, err := openhabProbe{}.Probe(context.Background(), target(pageServer(t, "/rest/", 200, raw), "openhab"))
	if err != nil || obs.Version != "5.2.2" || obs.Extra["build"] != "Release Build" || obs.Extra["restApiVersion"] != "8" {
		t.Fatalf("got %q %+v, %v", obs.Version, obs.Extra, err)
	}
	if _, err := (openhabProbe{}).Probe(context.Background(), target(pageServer(t, "/rest/", 200, []byte(`{"version":"8"}`)), "openhab")); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}
