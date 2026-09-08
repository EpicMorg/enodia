// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// unameFamilyProbe identifies a BSD by SSHing in and running `uname -sr` —
// neither OpenBSD nor NetBSD ships an os-release-equivalent file (unlike
// FreeBSD's /var/run/os-release, see osrelease.go), so `uname -sr`'s
// "<Kernel name> <release>" is the identity source instead (D9: checked
// against the kernel name, not assumed).
//
// Verified live against real systems, not documentation: both were
// unreachable from this environment directly (no Docker image, no
// downloadable pre-installed VM image for either — see DECISIONS.md D23),
// so both were captured via vmactions' GitHub Actions (github.com/vmactions/
// openbsd-vm, netbsd-vm — real QEMU-booted, pre-built VM images, not
// something built or guessed at here) — `uname -sr` gave exactly
// "OpenBSD 7.9" and "NetBSD 11.0", each with no hostname in it at all
// (unlike `uname -a`, which this probe deliberately does not use).
type unameFamilyProbe struct {
	product   string
	summary   string
	resolver  ResolverRef
	unameName string // expected first field of `uname -sr`, e.g. "OpenBSD"
}

func (p unameFamilyProbe) Meta() Meta {
	return Meta{
		Product: p.product,
		Summary: p.summary,
		Auth:    AuthSpec{Required: true, Kinds: []AuthKind{AuthPassword, AuthSSHKey}},
		// DefaultScheme left empty: SSH has no URL-scheme concept (D10).
		DefaultResolver: p.resolver,
	}
}

func (p unameFamilyProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	const cmd = "uname -sr"
	out, verified, err := sshRunCommand(ctx, t, cmd)
	if err != nil {
		if isSSHExitError(err) {
			return obs, fmt.Errorf("%w: %q failed: %w", ErrNotSupported, cmd, err)
		}
		return obs, err
	}

	name, version, ok := strings.Cut(strings.TrimSpace(out), " ")
	if !ok {
		return obs, fmt.Errorf("%w: %q printed %q, not \"<name> <release>\"", ErrUnparseable, cmd, out)
	}
	if name != p.unameName {
		return obs, fmt.Errorf("%w: %q reports kernel name %q, not %s", ErrNotSupported, cmd, name, p.unameName)
	}

	obs.Version = version
	obs.Endpoint = cmd
	obs.Extra = map[string]string{"hostKeyVerified": strconv.FormatBool(verified)}
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}
