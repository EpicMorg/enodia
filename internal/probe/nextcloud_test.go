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

func loadNextcloudFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "nextcloud_34.0.3.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// nextcloud_34.0.3.json is a real /status.php reply captured from a live
// Nextcloud container, once installed and out of maintenance mode.
func TestNextcloudProbeParsesRealFixture(t *testing.T) {
	fixture := loadNextcloudFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status.php" {
			t.Errorf("got path %q, want /status.php", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := nextcloudProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "nextcloud"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "34.0.3" {
		t.Fatalf("got version %q, want the 3-part versionstring", obs.Version)
	}
	if obs.Extra["buildVersion"] != "34.0.3.2" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
	if obs.Extra["installed"] != "true" || obs.Extra["maintenance"] != "false" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

// A live instance still answers with its version and versionstring before
// setup has ever run (installed:false) and again once maintenance mode is
// on (maintenance:true) — both confirmed live via `occ`, and neither is
// this probe's call to turn into an error (D7).
func TestNextcloudProbeUninstalledAndMaintenanceAreNotErrors(t *testing.T) {
	for _, body := range []string{
		`{"installed":false,"maintenance":false,"needsDbUpgrade":false,"version":"34.0.3.2","versionstring":"34.0.3"}`,
		`{"installed":true,"maintenance":true,"needsDbUpgrade":false,"version":"34.0.3.2","versionstring":"34.0.3"}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		p := nextcloudProbe{}
		obs, err := p.Probe(context.Background(), target(srv.URL, "nextcloud"))
		srv.Close()
		if err != nil {
			t.Fatalf("Probe: %v", err)
		}
		if obs.Version != "34.0.3" {
			t.Fatalf("got version %q", obs.Version)
		}
	}
}

func TestNextcloudProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := nextcloudProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "nextcloud"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestNextcloudProbeMissingVersionField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"installed":true,"maintenance":false}`))
	}))
	defer srv.Close()

	p := nextcloudProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "nextcloud"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestNextcloudProbeMeta(t *testing.T) {
	m := nextcloudProbe{}.Meta()
	if m.Product != "nextcloud" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("this endpoint is intentionally public, confirmed live")
	}
	if len(m.Auth.Kinds) != 0 {
		t.Fatalf("got Kinds %+v, want none: no credentialed path was ever tested", m.Auth.Kinds)
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "nextcloud" {
		t.Fatalf("got resolver %+v, want endoflife/nextcloud", m.DefaultResolver)
	}
}
