// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

// p4dProbe reports the version of a direct Perforce Helix Core server
// (p4d) via `p4 -Ztag -p <address> info` — see p4info.go for why this
// shells out rather than speaking the wire protocol directly.
//
// No credentials needed: confirmed live against real production servers
// that `info` answers fully unauthenticated. No DefaultResolver: Perforce
// is proprietary, with no endoflife.date page (confirmed 404 for every
// slug tried) and no public GitHub releases to fall back on — this is
// inventory-only, the same as gentoo/kali-linux/openeuler/redos.
type p4dProbe struct{}

func (p4dProbe) Meta() Meta {
	return Meta{
		Product: "p4d",
		Summary: "Perforce Helix Core Server (p4d)",
		Auth:    AuthSpec{Required: false},
		// DefaultScheme left empty: this is a bare host:port, not a URL
		// (D10, same as mysql/redis).
	}
}

// p4dVersionPattern extracts the release ("2024.2") out of serverVersion's
// "P4D/LINUX26X86_64/2024.2/2726408 (2025/02/27)" shape. Deliberately not
// stored as-is in Observation.Version: internal/version.Core's numeric-
// spine regex would match the FIRST digit run anywhere in that string —
// "26" from "LINUX26X86_64" — not the actual release, since it has no
// anchor requiring a match at the start.
var p4dVersionPattern = regexp.MustCompile(`^P4D/[^/]+/(\d+\.\d+)(?:/|$)`)

func (p4dProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	fields, err := runP4Info(ctx, t)
	if err != nil {
		return obs, err
	}

	if proxyVersion, isProxy := fields["proxyVersion"]; isProxy {
		return obs, fmt.Errorf("%w: this address answers as a Perforce Proxy (proxyVersion=%q) — use product: p4p",
			ErrNotSupported, proxyVersion)
	}

	raw := fields["serverVersion"]
	m := p4dVersionPattern.FindStringSubmatch(raw)
	if m == nil {
		return obs, fmt.Errorf("%w: serverVersion %q is not a recognized P4D version string", ErrUnparseable, raw)
	}

	obs.Version = m[1]
	obs.Extra = map[string]string{"raw": raw}
	if id := fields["ServerID"]; id != "" {
		obs.Extra["serverID"] = id
	}
	if svc := fields["serverServices"]; svc != "" {
		obs.Extra["serverServices"] = svc
	}
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}
