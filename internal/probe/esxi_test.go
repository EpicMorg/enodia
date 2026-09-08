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

func loadESXiFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "esxi_8.0.3.xml"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// esxi_8.0.3.xml is a real RetrieveServiceContent reply captured from a
// live, production ESXi 8.0.3 host, with no credentials at all.
func TestESXiProbeParsesRealFixture(t *testing.T) {
	fixture := loadESXiFixture(t)
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

	p := esxiProbe{}
	obs, err := p.Probe(context.Background(), target(srv.URL, "esxi"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "8.0.3" {
		t.Fatalf("got version %q", obs.Version)
	}
	if obs.Extra["build"] != "25067014" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

// D9: product: esxi pointed at a real vCenter must fail, not silently
// report vCenter's version as ESXi's. Not captured from a live vCenter
// (only an ESXi host was available to verify against) — apiType is the
// one field this synthetic reply changes from the real ESXi fixture,
// matching VMware's own documented apiType values (HostAgent vs
// VirtualCenter).
func TestESXiProbeRejectsVirtualCenterAPIType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
<soapenv:Body><RetrieveServiceContentResponse xmlns="urn:vim25"><returnval><about>
<name>VMware vCenter Server</name><fullName>VMware vCenter Server 8.0.3</fullName>
<version>8.0.3</version><build>12345</build><apiType>VirtualCenter</apiType>
</about></returnval></RetrieveServiceContentResponse></soapenv:Body></soapenv:Envelope>`))
	}))
	defer srv.Close()

	p := esxiProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "esxi"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestESXiProbeMalformedXML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not xml"))
	}))
	defer srv.Close()

	p := esxiProbe{}
	_, err := p.Probe(context.Background(), target(srv.URL, "esxi"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestESXiProbeMeta(t *testing.T) {
	m := esxiProbe{}.Meta()
	if m.Product != "esxi" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("RetrieveServiceContent needs no credentials")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "esxi" {
		t.Fatalf("got resolver %+v, want endoflife/esxi", m.DefaultResolver)
	}
}
