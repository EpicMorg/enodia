// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// nexusProbe reads the "Server" response header Sonatype Nexus Repository
// sets on every reply, the same shape as nginx.go/apache.go — but hitting
// the purpose-built anonymous status endpoint rather than "/", since that
// one is a fast, empty-bodied health check rather than the full portal
// page.
//
// Confirmed live against a real sonatype/nexus3 container:
// "Nexus/3.96.0-09 (COMMUNITY)" on the status endpoint, the portal page,
// and a 401 challenge from a different, actually-protected endpoint alike
// — unlike nginx/Apache, no config toggle to strip this to a bare "Nexus"
// is documented or was found, but the parsing still degrades to
// ErrNotSupported rather than a panic if a future version or a
// reverse-proxying setup ever does.
type nexusProbe struct{}

func (nexusProbe) Meta() Meta {
	return Meta{
		Product:         "nexus",
		Summary:         "Sonatype Nexus Repository",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "nexus"},
	}
}

func (nexusProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path: "/service/rest/v1/status",
	})
	if err != nil {
		return obs, err
	}
	defer resp.Body.Close()
	obs.Endpoint = resp.Request.URL.Path
	obs.DurationMS = time.Since(start).Milliseconds()

	server := resp.Header.Get("Server")
	name, rest, _ := strings.Cut(server, "/")
	if name != "Nexus" {
		return obs, fmt.Errorf("%w: Server header is %q, not a Nexus/<version> one", ErrNotSupported, server)
	}
	if rest == "" {
		return obs, fmt.Errorf("%w: Server header carries no version", ErrNotSupported)
	}
	// Cut on the first space: the version is followed by "(COMMUNITY)" or
	// "(PRO)" — the edition, which product: nexus already implies rather
	// than needing to be recorded per-target.
	version, _, _ := strings.Cut(rest, " ")

	obs.Version = version
	return obs, nil
}
