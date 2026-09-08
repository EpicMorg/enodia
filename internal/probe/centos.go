// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// centosProbe identifies legacy, EOL CentOS Linux (as opposed to
// centos-stream, its still-current successor) by SSHing in and reading
// /etc/redhat-release. This isn't part of osReleaseFamilyProbe: confirmed
// live that CentOS 5 and 6 predate the systemd os-release convention
// entirely (no /etc/os-release at all), while /etc/redhat-release has
// existed across every RHEL-family release from long before that. Real
// fleets still run these — CentOS reaching EOL doesn't retire the machines
// still running it, which is the whole point of tracking a dead product.
//
// Confirmed live across centos:5 ("CentOS release 5.11 (Final)"), :6
// ("CentOS release 6.10 (Final)"), and :7 ("CentOS Linux release 7.9.2009
// (Core)") — all match centosReleasePattern. CentOS Stream 9's own
// /etc/redhat-release ("CentOS Stream release 9") does not: the pattern
// requires "CentOS release" or "CentOS Linux release" immediately, and
// "CentOS Stream release" satisfies neither, so centos-stream instances
// are never misidentified as this product even though both files exist
// on both product lines.
type centosProbe struct{}

func (centosProbe) Meta() Meta {
	return Meta{
		Product: "centos",
		Summary: "CentOS Linux (legacy, EOL)",
		Auth:    AuthSpec{Required: true, Kinds: []AuthKind{AuthPassword, AuthSSHKey}},
		// DefaultScheme left empty: SSH has no URL-scheme concept (D10).
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "centos"},
	}
}

var centosReleasePattern = regexp.MustCompile(`^CentOS (?:Linux )?release (\d+(?:\.\d+)*)`)

func (centosProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	const cmd = "cat /etc/redhat-release"
	out, verified, err := sshRunCommand(ctx, t, cmd)
	if err != nil {
		if isSSHExitError(err) {
			return obs, fmt.Errorf("%w: %q: no such file (not a RHEL-family Linux): %w", ErrNotSupported, cmd, err)
		}
		return obs, err
	}

	m := centosReleasePattern.FindStringSubmatch(out)
	if m == nil {
		return obs, fmt.Errorf("%w: /etc/redhat-release reads %q, not CentOS (or it's CentOS Stream — product: centos-stream)", ErrNotSupported, out)
	}

	obs.Version = m[1]
	obs.Endpoint = "/etc/redhat-release"
	obs.Extra = map[string]string{"hostKeyVerified": strconv.FormatBool(verified)}
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}
