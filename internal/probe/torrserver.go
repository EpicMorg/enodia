// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// torrserverProbe reads GET /echo, which TorrServer answers with its
// version as plain text: "MatriX.146" (confirmed live on
// ghcr.io/yourok/torrserver:latest; its GitHub releases are tagged the same
// way, MatriX.146, MatriX.145.2). version.Core compares the numbers after
// the codename. Basic credentials are sent if configured, for an instance
// with its own auth turned on.
type torrserverProbe struct{}

func (torrserverProbe) Meta() Meta {
	return Meta{
		Product:         "torrserver",
		Summary:         "TorrServer",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false, Kinds: []AuthKind{AuthBasic}},
		DefaultResolver: ResolverRef{Type: "github", ID: "YouROK/TorrServer"},
	}
}

var torrserverVersionPattern = regexp.MustCompile(`^[A-Za-z]+\.\d+(?:\.\d+)*$`)

func (torrserverProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}
	resp, err := FetchHTTP(ctx, t, Request{Path: "/echo"})
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
	v := strings.TrimSpace(string(body))
	if !torrserverVersionPattern.MatchString(v) {
		return obs, fmt.Errorf("%w: /echo answered %q (not TorrServer?)", ErrNotSupported, v)
	}
	obs.Version = v
	return obs, nil
}
