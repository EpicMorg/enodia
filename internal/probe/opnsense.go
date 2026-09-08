// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// opnsenseProbe identifies OPNsense by SSHing in and running
// `opnsense-version`. OPNsense sits on a FreeBSD base (`uname -a` reports
// "FreeBSD ... stable/26.7-..." — the FreeBSD release, not OPNsense's own),
// carries no /etc/os-release at all, and its actual version lives under
// /usr/local/opnsense/version/ as several separate component files (base,
// kernel, core, pkgs); `opnsense-version` is OPNsense's own wrapper that
// reads the right one and prints "OPNsense <version> (<arch>)" — the same
// identity-plus-version shape D9 wants in one command instead of picking
// through component files by hand.
//
// Verified live against a real OPNsense 26.7 instance, reached via
// vmactions/opnsense-vm (no Docker image or downloadable pre-installed
// image exists otherwise for an appliance OS like this).
type opnsenseProbe struct{}

func (opnsenseProbe) Meta() Meta {
	return Meta{
		Product: "opnsense",
		Summary: "OPNsense",
		Auth:    AuthSpec{Required: true, Kinds: []AuthKind{AuthPassword, AuthSSHKey}},
		// DefaultScheme left empty: SSH has no URL-scheme concept (D10).
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "opnsense"},
	}
}

// opnsenseVersionPattern matches `opnsense-version`'s real output shape,
// confirmed live: "OPNsense 26.7 (amd64)".
var opnsenseVersionPattern = regexp.MustCompile(`^OPNsense (\S+)`)

func (opnsenseProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	const cmd = "opnsense-version"
	out, verified, err := sshRunCommand(ctx, t, cmd)
	if err != nil {
		if isSSHExitError(err) {
			return obs, fmt.Errorf("%w: %q: command not found (not OPNsense): %w", ErrNotSupported, cmd, err)
		}
		return obs, err
	}

	m := opnsenseVersionPattern.FindStringSubmatch(out)
	if m == nil {
		return obs, fmt.Errorf("%w: %q printed %q, not \"OPNsense <version> ...\"", ErrNotSupported, cmd, out)
	}

	obs.Version = m[1]
	obs.Endpoint = cmd
	obs.Extra = map[string]string{"hostKeyVerified": strconv.FormatBool(verified)}
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}
