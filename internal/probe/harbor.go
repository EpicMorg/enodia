// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// harborProbe reads /api/v2.0/systeminfo.
//
// Confirmed live against a real goharbor/harbor v2.12.2 stack (core, db,
// redis, registry, portal, jobservice — installed via the official
// docker-compose installer, not a single container): harbor_version comes
// back with no credentials at all, and bad or fabricated Basic/Bearer
// credentials are silently treated as anonymous rather than answering 401 —
// this endpoint never rejects a request, it only adds fields once actually
// authenticated.
//
// That last point matters going forward: Harbor's own source (as of the
// commit reviewed for this probe) already gates harbor_version behind
// `sc.IsAuthenticated()` on main, unreleased at the time of writing but
// visibly heading toward every future release requiring credentials for
// this field — every currently-released version still returns it
// anonymously. AuthBasic is offered here for when that lands.
type harborProbe struct{}

func (harborProbe) Meta() Meta {
	return Meta{
		Product:         "harbor",
		Summary:         "Harbor (container registry)",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false, Kinds: []AuthKind{AuthBasic}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "harbor"},
	}
}

// harborSystemInfo is the subset of /api/v2.0/systeminfo this probe reads.
// Verified against a live server's real JSON reply (see
// testdata/harbor_2.12.2.json).
type harborSystemInfo struct {
	HarborVersion string `json:"harbor_version"`
}

func (harborProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/api/v2.0/systeminfo",
		Accept: "application/json",
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

	var info harborSystemInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: /api/v2.0/systeminfo is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.HarborVersion == "" {
		return obs, fmt.Errorf("%w: /api/v2.0/systeminfo carries no harbor_version "+
			"(anonymous on every release today, but this deployment may already "+
			"require authentication for it — see the type comment)", ErrNotSupported)
	}

	obs.Version = info.HarborVersion
	return obs, nil
}
