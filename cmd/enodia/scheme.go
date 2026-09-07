// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/EpicMorg/enodia/internal/probe"
)

// resolveScheme tries https, then http, against addr (which carries no
// explicit scheme), sending no credentials. Per D12, https is always tried
// first: the alternative — trying http first — would put a credential on
// the wire in the clear on the very first request, and a later redirect
// does not un-send it. tlsSettings carries the target's own CA/pin
// configuration so a corporate CA is honoured on the https attempt rather
// than failing it outright.
//
// Any response at all, including a 4xx or 5xx one, counts as "this scheme
// reached the host" — resolveScheme is deciding transport, not checking
// whether a particular path exists.
func resolveScheme(ctx context.Context, addr string, tlsSettings probe.TLSSettings, timeout time.Duration) (string, error) {
	httpsClient, err := probe.NewHTTPClient(tlsSettings, timeout)
	if err != nil {
		return "", fmt.Errorf("building TLS client: %w", err)
	}

	attempts := []struct {
		scheme string
		client *http.Client
	}{
		{"https", httpsClient},
		{"http", &http.Client{Timeout: timeout}},
	}

	var lastErr error
	for _, a := range attempts {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, a.scheme+"://"+addr, nil)
		if err != nil {
			return "", fmt.Errorf("building request: %w", err)
		}
		resp, err := a.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		return a.scheme, nil
	}
	return "", fmt.Errorf("neither https nor http reached %s: %w", addr, lastErr)
}
