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

func loadZouFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "zou_1.0.56.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// zou_1.0.56.json is a real /api/status reply captured from a live
// production instance reachable at a "kitsu"-named host — the response
// itself says "name":"Zou", confirming Zou (the backend), not Kitsu (the
// frontend), is what actually answers this endpoint.
func TestZouProbeParsesRealFixture(t *testing.T) {
	fixture := loadZouFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/status" {
			t.Errorf("got path %q, want /api/status", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := zouFamilyProbe{product: "zou"}
	obs, err := p.Probe(context.Background(), target(srv.URL, "zou"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "1.0.56" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["databaseUp"] != "true" || obs.Extra["indexerUp"] != "true" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

func TestZouProbeWrongNameIsErrNotSupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"name":"SomethingElse","version":"1.0.0"}`))
	}))
	defer srv.Close()

	p := zouFamilyProbe{product: "zou"}
	_, err := p.Probe(context.Background(), target(srv.URL, "zou"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestZouProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := zouFamilyProbe{product: "zou"}
	_, err := p.Probe(context.Background(), target(srv.URL, "zou"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestZouProbeMissingVersionField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"name":"Zou"}`))
	}))
	defer srv.Close()

	p := zouFamilyProbe{product: "zou"}
	_, err := p.Probe(context.Background(), target(srv.URL, "zou"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

// zou and kitsu are two distinct products (not product+alias) precisely so
// they can carry different resolvers: cgwire/zou has no GitHub Releases at
// all (bare tags only, confirmed live), while cgwire/kitsu does and is
// what a "kitsu"-named deployment actually tracks.
func TestZouFamilyProbeMeta(t *testing.T) {
	zou := zouFamilyProbe{product: "zou", summary: "Zou (CG-Wire API backend)"}.Meta()
	kitsu := zouFamilyProbe{
		product: "kitsu", summary: "Kitsu (CG-Wire / Zou frontend)",
		resolver: ResolverRef{Type: "github", ID: "cgwire/kitsu"},
	}.Meta()

	if zou.Product != "zou" || kitsu.Product != "kitsu" {
		t.Fatalf("got products %q, %q, want distinct zou/kitsu", zou.Product, kitsu.Product)
	}
	for _, m := range []Meta{zou, kitsu} {
		if m.Auth.Required {
			t.Fatalf("%s: this endpoint is intentionally public, confirmed live", m.Product)
		}
	}
	if zou.DefaultResolver.Type != "" {
		t.Fatalf("zou: got resolver %+v, want none (cgwire/zou has no GitHub Releases at all)", zou.DefaultResolver)
	}
	if kitsu.DefaultResolver.Type != "github" || kitsu.DefaultResolver.ID != "cgwire/kitsu" {
		t.Fatalf("kitsu: got resolver %+v, want github/cgwire/kitsu", kitsu.DefaultResolver)
	}
}

func TestZouAndKitsuAreDistinctProducts(t *testing.T) {
	kitsu, err := Get("kitsu")
	if err != nil {
		t.Fatalf("Get(\"kitsu\"): %v", err)
	}
	if kitsu.Meta().Product != "kitsu" {
		t.Fatalf("got product %q via \"kitsu\", want \"kitsu\" (not an alias of zou anymore)", kitsu.Meta().Product)
	}
}
