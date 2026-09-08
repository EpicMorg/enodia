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

func loadPhpMyAdminFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "phpmyadmin_5.2.3.html"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// phpmyadmin_5.2.3.html is a real "/" (login page) reply captured from a
// live phpmyadmin/phpmyadmin container with no credentials at all — the
// CSRF token has been scrubbed.
func TestPhpMyAdminProbeParsesRealFixture(t *testing.T) {
	fixture := loadPhpMyAdminFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			t.Errorf("got path %q, want /", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := phpmyadminProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "phpmyadmin"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "5.2.3" {
		t.Fatalf("got version %q", obs.Version)
	}
}

func TestPhpMyAdminProbeWrongProduct(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>not phpmyadmin at all</body></html>"))
	}))
	defer srv.Close()

	p := phpmyadminProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "phpmyadmin"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestPhpMyAdminProbeMeta(t *testing.T) {
	m := phpmyadminProbe{}.Meta()
	if m.Product != "phpmyadmin" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("the login page needs no credentials")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "phpmyadmin" {
		t.Fatalf("got resolver %+v, want endoflife/phpmyadmin", m.DefaultResolver)
	}
}
