// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"time"
)

// greenboneProbe reads the version of gsad, Greenbone's web daemon (the
// Greenbone Security Assistant in front of OpenVAS), from the envelope it
// wraps every /gmp reply in — the 401 for a request without a session
// included: "<envelope><version>24.12.0</version>...<title>Authentication
// required: ... (GSA 24.12.0)</title>...". Confirmed live on a production
// Greenbone Community Edition; testdata/greenbone_gsad_24.12.0_gmp.xml is
// that reply verbatim. The web UI's own pages are a static React bundle
// with no version in them.
type greenboneProbe struct{}

func (greenboneProbe) Meta() Meta {
	return Meta{
		Product:       "greenbone",
		Aliases:       []string{"openvas", "gsad"},
		Summary:       "Greenbone / OpenVAS (gsad web daemon)",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false},
		// No endoflife.date page; gsad's own releases.
		DefaultResolver: ResolverRef{Type: "github", ID: "greenbone/gsad"},
	}
}

type gsadEnvelope struct {
	XMLName       xml.Name `xml:"envelope"`
	Version       string   `xml:"version"`
	VendorVersion string   `xml:"vendor_version"`
}

func (greenboneProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{Path: "/gmp", OKStatuses: []int{http.StatusUnauthorized}})
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
	var env gsadEnvelope
	if err := xml.Unmarshal(body, &env); err != nil || env.Version == "" {
		return obs, fmt.Errorf("%w: /gmp gave no gsad <envelope><version> (not Greenbone?)", ErrNotSupported)
	}
	obs.Version = env.Version
	if env.VendorVersion != "" {
		obs.Extra = map[string]string{"vendorVersion": env.VendorVersion}
	}
	return obs, nil
}
