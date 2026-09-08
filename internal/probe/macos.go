// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// macosProbe identifies macOS by SSHing in and running sw_vers — the
// standard, documented way to read a Mac's OS identity, deliberately not
// `uname -a`: Darwin's uname reports the machine's own hostname as part of
// its output, which this probe has no reason to see or record, while
// sw_vers's three-line ProductName/ProductVersion/BuildVersion carries none
// of that.
//
// Verified live against a real Mac (macOS 15.4, BuildVersion 24E248, over
// SSH) — the only registration in this project that needed a live macOS
// target rather than a container or a downloadable VM image, since Apple's
// EULA restricts macOS virtualization to genuine Apple hardware (see
// DECISIONS.md D23, written before this target became available).
type macosProbe struct{}

func (macosProbe) Meta() Meta {
	return Meta{
		Product: "macos",
		Summary: "macOS",
		Auth:    AuthSpec{Required: true, Kinds: []AuthKind{AuthPassword, AuthSSHKey}},
		// DefaultScheme left empty: SSH has no URL-scheme concept (D10).
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "macos"},
	}
}

func (macosProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	const cmd = "sw_vers"
	out, verified, err := sshRunCommand(ctx, t, cmd)
	if err != nil {
		if isSSHExitError(err) {
			return obs, fmt.Errorf("%w: %q: command not found (not macOS): %w", ErrNotSupported, cmd, err)
		}
		return obs, err
	}

	fields := parseSwVers(out)
	// Only "macOS" (10.12 Sierra onward) is verified live; older releases
	// reported ProductName "Mac OS X" instead, and that shape has never
	// been seen against a real system by this probe, so it is treated as
	// not supported rather than guessed at.
	if fields["ProductName"] != "macOS" {
		return obs, fmt.Errorf("%w: sw_vers reports ProductName=%q, not macOS", ErrNotSupported, fields["ProductName"])
	}

	version, ok := fields["ProductVersion"]
	if !ok {
		return obs, fmt.Errorf("%w: sw_vers output has no ProductVersion field", ErrUnparseable)
	}

	obs.Version = version
	obs.Endpoint = cmd
	extra := map[string]string{"hostKeyVerified": strconv.FormatBool(verified)}
	if build, ok := fields["BuildVersion"]; ok {
		extra["buildVersion"] = build
	}
	obs.Extra = extra
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}

// parseSwVers parses sw_vers's "Key:\t\tValue" lines. Real output never
// needs more than a colon split plus whitespace trimming (verified against
// a live Mac).
func parseSwVers(raw string) map[string]string {
	fields := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields[strings.TrimSpace(key)] = strings.TrimSpace(val)
	}
	return fields
}
