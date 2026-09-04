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
	raw, err := os.ReadFile(filepath.Join("testdata", "vcenter_8.0.3.0.xml"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// vcenter_8.0.3.0.xml is a real /sdk/vimServiceVersions.xml reply captured
// from a live production vCenter instance.
func TestVCenterProbeParsesRealFixture(t *testing.T) {
	fixture := loadVCenterFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sdk/vimServiceVersions.xml" {
			t.Errorf("got path %q, want /sdk/vimServiceVersions.xml", r.URL.Path)
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
	if obs.Version != "8.0.3.0" {
		t.Fatalf("got version %q, want the current urn:vim25 version, not one from priorVersions", obs.Version)
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

func TestVCenterProbeNoVim25Namespace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<namespaces version="1.0"><namespace><name>urn:pbm</name><version>2.0</version></namespace></namespaces>`))
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
		t.Fatal("this endpoint is intentionally public, confirmed live")
	}
	if len(m.Auth.Kinds) != 0 {
		t.Fatalf("got Kinds %+v, want none: no credentialed path was ever tested", m.Auth.Kinds)
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "vcenter" {
		t.Fatalf("got resolver %+v, want endoflife/vcenter", m.DefaultResolver)
	}
}
