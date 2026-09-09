// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

// p4pProbe reports the version of a Perforce Proxy (p4p) via `p4 -Ztag -p
// <address> info` — see p4info.go for why this shells out rather than
// speaking the wire protocol directly.
//
// Confirmed live: a proxy answers `info` with everything a direct p4d
// does, PLUS its own proxyVersion field naming itself — the backend
// server's serverVersion/ServerID/serverServices all come through
// unchanged, describing the server behind the proxy, not the proxy
// itself. p4dProbe rejects a reply carrying proxyVersion (D9: the two
// products must reject each other's real reply, not just parse whatever
// version comes back); this probe requires the opposite.
type p4pProbe struct{}

func (p4pProbe) Meta() Meta {
	return Meta{
		Product: "p4p",
		Summary: "Perforce Proxy (p4p)",
		Auth:    AuthSpec{Required: false},
		// DefaultScheme left empty: bare host:port, not a URL (D10).
		// No DefaultResolver: same reasoning as p4dProbe — Perforce is
		// proprietary, no public lifecycle calendar exists for it.
	}
}

// p4pVersionPattern extracts the release ("2024.2") out of proxyVersion's
// "P4P/LINUX26X86_64/2024.2/2832881 (2025/09/30)" shape — same anchoring
// reasoning as p4dVersionPattern.
var p4pVersionPattern = regexp.MustCompile(`^P4P/[^/]+/(\d+\.\d+)(?:/|$)`)

func (p4pProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	fields, err := runP4Info(ctx, t)
	if err != nil {
		return obs, err
	}

	raw, isProxy := fields["proxyVersion"]
	if !isProxy {
		return obs, fmt.Errorf("%w: this address answers as a direct Perforce server (no proxyVersion field) — use product: p4d",
			ErrNotSupported)
	}

	m := p4pVersionPattern.FindStringSubmatch(raw)
	if m == nil {
		return obs, fmt.Errorf("%w: proxyVersion %q is not a recognized P4P version string", ErrUnparseable, raw)
	}

	obs.Version = m[1]
	obs.Extra = map[string]string{"raw": raw}
	if sv := fields["serverVersion"]; sv != "" {
		obs.Extra["backendServerVersion"] = sv
	}
	if id := fields["ServerID"]; id != "" {
		obs.Extra["backendServerID"] = id
	}
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}
