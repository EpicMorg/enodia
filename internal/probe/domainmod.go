// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

// domainmodProbe reads the CHANGELOG that ships in DomainMOD's web root and
// is served as a static file: "DomainMOD CHANGELOG", then the newest entry
// first, "v4.23.0     2025-01-04" (confirmed live on
// domainmod/domainmod:latest, whose software.inc.php says SOFTWARE_VERSION
// = '4.23.0'). The UI shows "Version 4.23.0" only in the layout's footer
// after login, so the CHANGELOG is what's anonymous. A DomainMOD under a
// sub-path (DOMAINMOD_WEB_ROOT) is reached by putting it in the address.
type domainmodProbe struct{}

func (domainmodProbe) Meta() Meta {
	return Meta{
		Product:         "domainmod",
		Summary:         "DomainMOD",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "github", ID: "domainmod/domainmod"},
	}
}

var domainmodChangelogPattern = regexp.MustCompile(`(?s)^\s*DomainMOD CHANGELOG\s*=+\s*v(\d+(?:\.\d+)+)\s`)

func (domainmodProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}
	resp, err := FetchHTTP(ctx, t, Request{Path: "/CHANGELOG"})
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
	m := domainmodChangelogPattern.FindSubmatch(body)
	if m == nil {
		return obs, fmt.Errorf("%w: /CHANGELOG is not DomainMOD's (not DomainMOD, or the file is blocked)", ErrNotSupported)
	}
	obs.Version = string(m[1])
	return obs, nil
}
