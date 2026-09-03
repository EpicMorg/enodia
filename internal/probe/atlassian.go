// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/xml"
	"fmt"
	"time"
)

// atlassianProbe reads the Application Links manifest that every Atlassian
// Data Center product exposes. The endpoint is anonymous, which is why it is
// preferred over /rest/api/2/serverInfo — no token needed to read a version.
//
// One instance is registered per product. The manifest reports which product
// it belongs to, so a URL pointed at the wrong entry is caught rather than
// silently recorded under the wrong name.
//
// Data Center only. Atlassian Cloud does not expose this.
type atlassianProbe struct {
	product  string
	typeID   string // expected <typeId>; Bitbucket still reports "stash"
	resolver string // endoflife.date slug, empty when there is none
	summary  string
}

type applinksManifest struct {
	XMLName     xml.Name `xml:"applinks-manifest"`
	TypeID      string   `xml:"typeId"`
	Version     string   `xml:"version"`
	BuildNumber string   `xml:"buildNumber"`
	Name        string   `xml:"name"`
}

func (p *atlassianProbe) Meta() Meta {
	m := Meta{
		Product:       p.product,
		Summary:       p.summary,
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false, Kinds: []AuthKind{AuthNone, AuthBasic, AuthBearer}},
	}
	if p.resolver != "" {
		m.DefaultResolver = ResolverRef{Type: "endoflife", ID: p.resolver}
	}
	return m
}

func (p *atlassianProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: p.product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/rest/applinks/1.0/manifest",
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

	var m applinksManifest
	if err := xml.Unmarshal(body, &m); err != nil {
		return obs, fmt.Errorf("%w: applinks manifest is not valid XML: %w", ErrUnparseable, err)
	}
	if m.Version == "" {
		return obs, fmt.Errorf("%w: applinks manifest carries no <version>", ErrUnparseable)
	}

	// Vendor identity check. This is the whole point of naming the product
	// explicitly in config: a Confluence URL under product: jira is a typo,
	// and saying so beats recording a wrong fact.
	if m.TypeID != "" && m.TypeID != p.typeID {
		return obs, fmt.Errorf("%w: this host reports typeId=%q, expected %q for product %q",
			ErrNotSupported, m.TypeID, p.typeID, p.product)
	}

	obs.Version = m.Version
	obs.Extra = map[string]string{}
	if m.BuildNumber != "" {
		obs.Extra["buildNumber"] = m.BuildNumber
	}
	if m.TypeID != "" {
		obs.Extra["typeId"] = m.TypeID
	}
	return obs, nil
}
