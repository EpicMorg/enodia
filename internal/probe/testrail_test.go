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

// testrail_9.1.0.1025.txt is the real, verbatim content of /version.txt
// captured from a live production TestRail instance — TestRail ships it as
// a plain static file, not a REST API response.
func TestTestrailProbeParsesRealResponse(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "testrail_9.1.0.1025.txt"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version.txt" {
			t.Errorf("got path %q, want /version.txt", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := testrailProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "testrail"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "9.1.0.1025" {
		t.Fatalf("got version %q", obs.Version)
	}
}

func TestTestrailProbeEmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("   \n"))
	}))
	defer srv.Close()

	p := testrailProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "testrail"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestTestrailProbeMeta(t *testing.T) {
	m := testrailProbe{}.Meta()
	if m.Product != "testrail" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("this endpoint is intentionally public, confirmed live")
	}
	if len(m.Auth.Kinds) != 0 {
		t.Fatalf("got Kinds %+v, want none: no credentialed path was ever tested", m.Auth.Kinds)
	}
	if m.DefaultResolver.Type != "" {
		t.Fatalf("got resolver %+v, want none (endoflife.date has no testrail calendar)", m.DefaultResolver)
	}
}
