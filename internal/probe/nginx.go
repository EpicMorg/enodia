// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// nginxProbe reads the "Server" response header nginx sets on every reply.
// There is no version endpoint: nginx (unlike NGINX Plus's REST API) exposes
// nothing else anonymously — ngx_http_stub_status_module's /stub_status
// gives connection counters, never a version.
//
// Any status code is accepted: nginx stamps its own Server header on error
// pages and redirects the same as on a 200, so a target whose "/" happens to
// 404 or sit behind a basic-auth vhost still reports a version just fine.
// Confirmed live against real nginx:1.27.4 containers for both cases below.
type nginxProbe struct{}

func (nginxProbe) Meta() Meta {
	return Meta{
		Product:         "nginx",
		Summary:         "nginx",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "nginx"},
	}
}

func (nginxProbe) Probe(ctx context.Context, t Target) (Observation, error) {
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
	if name != "nginx" {
		return obs, fmt.Errorf("%w: Server header is %q, not an nginx/<version> one", ErrNotSupported, server)
	}
	if version == "" {
		// server_tokens off (nginx's own hardening setting, common in
		// production): the header is stamped as a bare "nginx" with no
		// version at all — this confirms the product but there is nothing
		// left anonymously to compare against a lifecycle calendar. Not a
		// wrong product and not a parser bug, but ErrNotSupported is the
		// closest existing sentinel: "not supported by this probe" reads
		// fine for "this deployment's own config makes what this probe
		// needs unavailable", the same sense postgres's and mysql's
		// unsupported-auth-method cases already use it in.
		return obs, fmt.Errorf("%w: server_tokens is off; Server header carries no version", ErrNotSupported)
	}
	// Cut again on the first space: some builds append " (extra info)"
	// after the version, e.g. a distro package's own suffix.
	version, _, _ = strings.Cut(version, " ")

	obs.Version = version
	return obs, nil
}
