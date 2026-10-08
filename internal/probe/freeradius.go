// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// freeradiusVersionCommand tries each name the server binary ships under
// — "freeradius" on Debian/Ubuntu, "radiusd" on RHEL-family and source
// builds — by name and then by its /usr/sbin path, since a non-login SSH
// session's PATH often lacks /usr/sbin. The trailing `|| true` keeps a
// host with none of them from failing the command; that case is reported
// as ErrNotSupported from the (missing) version line instead.
const freeradiusVersionCommand = "freeradius -v 2>&1 || radiusd -v 2>&1 || /usr/sbin/freeradius -v 2>&1 || /usr/sbin/radiusd -v 2>&1 || true"

// freeradiusVersionPattern reads `-v`'s first line, confirmed live
// against FreeRADIUS 3.2.10: "radiusd: FreeRADIUS Version 3.2.10 (git
// #9071ea041), for host x86_64-pc-linux-gnu".
var freeradiusVersionPattern = regexp.MustCompile(`FreeRADIUS Version (\d+(?:\.\d+)+)(?: \(git #([0-9a-f]+)\))?`)

// freeradiusProbe runs the server's own `-v` over SSH.
//
// RADIUS itself can't say: the protocol has no version exchange, and
// neither does FreeRADIUS's Status-Server reply — its dictionaries define
// no version attribute at all (checked in 3.2.10's
// dictionary.freeradius*), only statistics counters. So this is an SSH
// probe like pfsense, not a network one.
//
// A FreeRADIUS in a container is common — the one it was built against
// (a production 3.2.10) runs in Docker, with no freeradius binary on
// the host at all. options.container names the container; the command
// then runs through `docker exec` (or podman, options.container_runtime),
// which needs the SSH user to be allowed to use it.
type freeradiusProbe struct{}

func (freeradiusProbe) Meta() Meta {
	return Meta{
		Product: "freeradius",
		Summary: "FreeRADIUS",
		Auth:    AuthSpec{Required: true, Kinds: []AuthKind{AuthPassword, AuthSSHKey}},
		// DefaultScheme left empty: SSH has no URL-scheme concept (D10).
		//
		// No endoflife.date page (confirmed 404). FreeRADIUS tags releases
		// "release_3_2_10" and maintains 3.0.x and 3.2.x side by side, so
		// its tags are read per branch.
		DefaultResolver: ResolverRef{Type: "github-tag-branches", ID: "FreeRADIUS/freeradius-server"},
	}
}

func (freeradiusProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	cmd, err := containerCommand(t, freeradiusVersionCommand)
	if err != nil {
		return obs, err
	}
	out, verified, err := sshRunCommand(ctx, t, cmd)
	if err != nil {
		if isSSHExitError(err) {
			// Only `docker exec` itself can still exit nonzero here: no
			// such container, or no permission to use the runtime.
			return obs, fmt.Errorf("%w: %w", ErrNotSupported, err)
		}
		return obs, err
	}

	m := freeradiusVersionPattern.FindStringSubmatch(out)
	if m == nil {
		return obs, fmt.Errorf("%w: no FreeRADIUS version in the output of freeradius/radiusd -v (not installed here, or in a container — see options.%s)",
			ErrNotSupported, containerOption)
	}

	obs.Version = m[1]
	obs.Endpoint = "freeradius -v"
	obs.Extra = map[string]string{"hostKeyVerified": strconv.FormatBool(verified)}
	if m[2] != "" {
		obs.Extra["git"] = m[2]
	}
	if c := t.Options[containerOption]; c != "" {
		obs.Extra["container"] = c
	}
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}
