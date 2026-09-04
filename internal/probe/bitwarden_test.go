// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// /api/version returns a bare JSON string, not an object — confirmed live
// against a real Bitwarden instance ("2025.12.0") and a real Vaultwarden
// instance ("1.36.0"), both through the identical endpoint and shape.
func TestBitwardenFamilyProbeParsesRealResponse(t *testing.T) {
	cases := []struct {
		product, body, want string
	}{
		{"bitwarden", `"2025.12.0"`, "2025.12.0"},
		{"vaultwarden", `"1.36.0"`, "1.36.0"},
	}
	for _, c := range cases {
		t.Run(c.product, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/version" {
					t.Errorf("got path %q, want /api/version", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()

			p, err := Get(c.product)
			if err != nil {
				t.Fatalf("Get(%q): %v", c.product, err)
			}
			obs, err := p.Probe(context.Background(), target(srv.URL, c.product))
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if obs.Version != c.want {
				t.Fatalf("got version %q, want %q", obs.Version, c.want)
			}
		})
	}
}

func TestBitwardenFamilyProbeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := bitwardenFamilyProbe{product: "bitwarden", summary: "Bitwarden (self-hosted)"}
	_, err := p.Probe(context.Background(), target(srv.URL, "bitwarden"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestBitwardenFamilyProbeEmptyVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`""`))
	}))
	defer srv.Close()

	p := bitwardenFamilyProbe{product: "bitwarden", summary: "Bitwarden (self-hosted)"}
	_, err := p.Probe(context.Background(), target(srv.URL, "bitwarden"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

// Bitwarden and Vaultwarden must stay two distinct products — Vaultwarden
// is an independent Rust reimplementation of the API, not a Bitwarden
// fork, with its own version numbering that would never compare
// meaningfully against a Bitwarden lifecycle calendar.
func TestBitwardenFamilyProbeMeta(t *testing.T) {
	bw := bitwardenFamilyProbe{product: "bitwarden", summary: "Bitwarden (self-hosted)"}.Meta()
	vw := bitwardenFamilyProbe{product: "vaultwarden", summary: "Vaultwarden"}.Meta()

	if bw.Product != "bitwarden" || vw.Product != "vaultwarden" {
		t.Fatalf("got products %q, %q, want distinct bitwarden/vaultwarden", bw.Product, vw.Product)
	}
	for _, m := range []Meta{bw, vw} {
		if m.Auth.Required {
			t.Fatalf("%s: this endpoint is intentionally public, confirmed live", m.Product)
		}
		if len(m.Auth.Kinds) != 0 {
			t.Fatalf("%s: got Kinds %+v, want none: no credentialed path was ever tested", m.Product, m.Auth.Kinds)
		}
		if m.DefaultResolver.Type != "" {
			t.Fatalf("%s: got resolver %+v, want none (endoflife.date has neither calendar)", m.Product, m.DefaultResolver)
		}
	}
}
