// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// truenasProbe identifies TrueNAS by SSHing in and reading /etc/version —
// its own identity file, not part of osReleaseFamilyProbe: confirmed live
// that TrueNAS SCALE's own /etc/os-release reports the underlying Debian 12
// base instead (TrueNAS is a web appliance layered on top of it), the same
// D9 gap astra-linux's own VERSION_ID had. /etc/version has none of that: a
// plain "25.10.7", the real appliance release.
//
// This is an interim SSH-based probe. A real Proxmox-style HTTP API
// exists (TrueNAS's own documented REST API), which would be the better
// long-term fit for this project's usual HTTP-probe shape — but this one
// shipped first since a live SSH target arrived first; the plan is for the
// API version to take over once verified, with this staying as a fallback.
//
// No DefaultResolver wiring beyond what's here was needed: endoflife.date
// does have a real `truenas` calendar (confirmed live), cycle "25.10"
// matching this fixture's "25.10.7" exactly.
type truenasProbe struct{}

func (truenasProbe) Meta() Meta {
	return Meta{
		Product: "truenas",
		Summary: "TrueNAS",
		Auth:    AuthSpec{Required: true, Kinds: []AuthKind{AuthPassword, AuthSSHKey}},
		// DefaultScheme left empty: SSH has no URL-scheme concept (D10).
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "truenas"},
	}
}

var truenasVersionPattern = regexp.MustCompile(`^\d+(?:\.\d+)+$`)

func (truenasProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	const cmd = "cat /etc/version"
	out, verified, err := sshRunCommand(ctx, t, cmd)
	if err != nil {
		if isSSHExitError(err) {
			return obs, fmt.Errorf("%w: %q: no such file (not TrueNAS): %w", ErrNotSupported, cmd, err)
		}
		return obs, err
	}

	version := strings.TrimSpace(out)
	if !truenasVersionPattern.MatchString(version) {
		return obs, fmt.Errorf("%w: /etc/version contains %q, not a version number", ErrUnparseable, version)
	}

	obs.Version = version
	obs.Endpoint = "/etc/version"
	obs.Extra = map[string]string{"hostKeyVerified": strconv.FormatBool(verified)}
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}
