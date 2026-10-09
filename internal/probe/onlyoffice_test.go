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

// Fixtures are the real /index.html and /welcome/ replies of live
// onlyoffice/documentserver:latest (9.4.0) and nextcloud/aio-eurooffice
// (9.3.1) containers. welcome == "" serves /welcome/ as a 404, the way a
// server with the welcome page turned off answers.
func onlyofficeServer(t *testing.T, index, welcome string) string {
	t.Helper()
	read := func(name string) []byte {
		raw, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatalf("fixture: %v", err)
		}
		return raw
	}
	idx := read(index)
	var wel []byte
	if welcome != "" {
		wel = read(welcome)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.html":
			_, _ = w.Write(idx)
		case "/welcome/":
			if wel == nil {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(wel)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

var (
	onlyofficeProduct = onlyofficeFamilyProbe{product: "onlyoffice", brand: "ONLYOFFICE"}
	euroOfficeProduct = onlyofficeFamilyProbe{product: "euro-office", brand: "Euro-Office"}
)

func TestOnlyOfficeProbeRealFixtures(t *testing.T) {
	for _, tc := range []struct {
		probe                                 onlyofficeFamilyProbe
		index, welcome, version, build, brand string
	}{
		{onlyofficeProduct, "onlyoffice_9.4.0_index.txt", "onlyoffice_9.4.0_welcome.html", "9.4.0", "129", "ONLYOFFICE"},
		{euroOfficeProduct, "eurooffice_9.3.1_index.txt", "eurooffice_9.3.1_welcome.html", "9.3.1", "37", "Euro-Office"},
	} {
		addr := onlyofficeServer(t, tc.index, tc.welcome)
		obs, err := tc.probe.Probe(context.Background(), target(addr, tc.probe.product))
		if err != nil {
			t.Fatalf("%s: Probe: %v", tc.probe.product, err)
		}
		if obs.Version != tc.version || obs.Extra["build"] != tc.build || obs.Extra["brand"] != tc.brand || obs.Extra["edition"] != "community" {
			t.Fatalf("%s: got %q %+v", tc.probe.product, obs.Version, obs.Extra)
		}
	}
}

// The two answer /index.html identically; /welcome/ tells them apart.
func TestOnlyOfficeProbeRefusesTheOtherBrand(t *testing.T) {
	addr := onlyofficeServer(t, "eurooffice_9.3.1_index.txt", "eurooffice_9.3.1_welcome.html")
	_, err := onlyofficeProduct.Probe(context.Background(), target(addr, "onlyoffice"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}

	addr = onlyofficeServer(t, "onlyoffice_9.4.0_index.txt", "onlyoffice_9.4.0_welcome.html")
	if _, err := euroOfficeProduct.Probe(context.Background(), target(addr, "euro-office")); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestOnlyOfficeProbeWelcomePageOff(t *testing.T) {
	addr := onlyofficeServer(t, "eurooffice_9.3.1_index.txt", "")
	obs, err := euroOfficeProduct.Probe(context.Background(), target(addr, "euro-office"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "9.3.1" || obs.Extra["brand"] != "" {
		t.Fatalf("got %q %+v", obs.Version, obs.Extra)
	}
}

func TestOnlyOfficeProbeNotADocumentServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>nginx default</html>"))
	}))
	defer srv.Close()
	if _, err := onlyofficeProduct.Probe(context.Background(), target(srv.URL, "onlyoffice")); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}
