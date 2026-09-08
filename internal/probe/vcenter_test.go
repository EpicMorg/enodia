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

func loadVCenterFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "vcenter_8.0.3.xml"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// vcenter_8.0.3.xml is a real RetrieveServiceContent reply captured from a
// live, production vCenter 8.0.3 instance, with no credentials at all
// (instanceUuid scrubbed).
func TestVCenterProbeParsesRealFixture(t *testing.T) {
	fixture := loadVCenterFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sdk" {
			t.Errorf("got path %q, want /sdk", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("got method %q, want POST", r.Method)
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := vcenterProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "vcenter"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "8.0.3" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["build"] != "25092719" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

// D9: product: vcenter pointed at a real ESXi host must fail, not
// silently report ESXi's version as vCenter's. Uses the real esxi
// fixture, which carries apiType=HostAgent.
func TestVCenterProbeRejectsRealESXi(t *testing.T) {
	fixture := loadESXiFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	p := vcenterProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "vcenter"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestVCenterProbeMalformedXML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not xml"))
	}))
	defer srv.Close()

	p := vcenterProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "vcenter"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestVCenterProbeMeta(t *testing.T) {
	m := vcenterProbe{}.Meta()
	if m.Product != "vcenter" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("RetrieveServiceContent needs no credentials")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "vcenter" {
		t.Fatalf("got resolver %+v, want endoflife/vcenter", m.DefaultResolver)
	}
}
