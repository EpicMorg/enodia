// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/xml"
	"fmt"
	"time"
)

// vcenterProbe reads /sdk/vimServiceVersions.xml for the version.
//
// Confirmed live against a real production instance: this endpoint —
// vCenter's SOAP API version-discovery document — needs no credentials.
//
// What it reports is the vim25 API version (e.g. "8.0.3.0"), not a
// separately-tracked marketing build string; VMware's own documentation
// treats the two as equivalent, and every third-party tool that
// version-detects vCenter this way (this probe's own predecessor included)
// relies on exactly that correspondence.
type vcenterProbe struct{}

func (vcenterProbe) Meta() Meta {
	return Meta{
		Product:         "vcenter",
		Summary:         "VMware vCenter Server",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "vcenter"},
	}
}

// vimServiceVersions is vimServiceVersions.xml's shape. Verified against a
// live server's real reply (see testdata/vcenter_8.0.3.0.xml). priorVersions
// is deliberately not modeled: Go's XML decoder only populates the fields
// given a tag, so the versions nested inside it are never reached by the
// Version field below, which only ever binds to the direct child.
type vimServiceVersions struct {
	XMLName    xml.Name `xml:"namespaces"`
	Namespaces []struct {
		Name    string `xml:"name"`
		Version string `xml:"version"`
	} `xml:"namespace"`
}

func (vcenterProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/sdk/vimServiceVersions.xml",
		Accept: "application/xml, text/xml",
	})
	if err != nil {
		return obs, err
	}
	defer resp.Body.Close()
	obs.Endpoint = resp.Request.URL.Path
	obs.DurationMS = time.Since(start).Milliseconds()

	body, err := ReadBody(resp)
	if err != nil {
		return obs, err
	}

	var doc vimServiceVersions
	if err := xml.Unmarshal(body, &doc); err != nil {
		return obs, fmt.Errorf("%w: vimServiceVersions.xml is not valid XML: %w", ErrUnparseable, err)
	}

	for _, ns := range doc.Namespaces {
		if ns.Name == "urn:vim25" && ns.Version != "" {
			obs.Version = ns.Version
			return obs, nil
		}
	}
	return obs, fmt.Errorf("%w: vimServiceVersions.xml has no urn:vim25 namespace with a version", ErrUnparseable)
}
