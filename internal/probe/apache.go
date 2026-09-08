// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// apacheProbe reads the "Server" response header Apache httpd sets on every
// reply, the same shape of problem as nginx.go: no version endpoint exists,
// and any status code (not just 200) still carries the header.
//
// Confirmed live against real httpd:2.4 containers for both cases below:
// the default build answers "Apache/2.4.68 (Unix)"; `ServerTokens Prod`
// (Apache's own equivalent of nginx's server_tokens off, common hardening)
// strips it to a bare "Apache" with no version at all.
type apacheProbe struct{}

func (apacheProbe) Meta() Meta {
	return Meta{
		Product:       "apache",
		Aliases:       []string{"httpd"},
		Summary:       "Apache HTTP Server",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false},
		// endoflife.date's slug is "apache-http-server" — both "apache" and
		// "httpd" 301-redirect there (confirmed live); using the resolved
		// slug directly skips that hop on every resolve.
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "apache-http-server"},
	}
}

func (apacheProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:       "/",
		OKStatuses: []int{301, 302, 401, 403, 404, 500, 502, 503, 504},
	})
	if err != nil {
		return obs, err
	}
	defer resp.Body.Close()
	obs.Endpoint = resp.Request.URL.Path
	obs.DurationMS = time.Since(start).Milliseconds()

	server := resp.Header.Get("Server")
	name, version, _ := strings.Cut(server, "/")
	if name != "Apache" {
		return obs, fmt.Errorf("%w: Server header is %q, not an Apache/<version> one", ErrNotSupported, server)
	}
	if version == "" {
		// ServerTokens Prod: confirmed and identified, but nothing left
		// anonymously to compare against a lifecycle calendar. See nginx.go
		// for why ErrNotSupported is the sentinel used for this shape.
		return obs, fmt.Errorf("%w: ServerTokens is Prod; Server header carries no version", ErrNotSupported)
	}
	// Cut on the first space: the version is followed by "(Unix)",
	// "(Ubuntu)" or a module list under looser ServerTokens settings.
	version, _, _ = strings.Cut(version, " ")

	obs.Version = version
	return obs, nil
}
