// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// osReleaseFamilyProbe identifies a Linux distribution by SSHing in and
// reading /etc/os-release — the systemd-standardized identity file present
// on every distro registered against this family. Confirmed live, one real
// container per registration (see registry.go's comment next to each entry
// for exactly what its /etc/os-release reported): debian, ubuntu, fedora, a
// real Red Hat UBI9 image for rhel, rockylinux, almalinux, oraclelinux,
// amazonlinux, opensuse/leap, alpine, a real CentOS Stream 9 image, and
// vbatts/slackware (Slackware 14.2, which turned out to ship os-release too,
// not just the historically-documented /etc/slackware-version).
//
// D9 (product declared explicitly, probe verifies): most distros are a
// plain ID== check, but two needed more — see match's doc on each
// registration.
type osReleaseFamilyProbe struct {
	product  string
	summary  string
	resolver ResolverRef
	match    func(fields map[string]string) bool
}

func (p osReleaseFamilyProbe) Meta() Meta {
	return Meta{
		Product: p.product,
		Summary: p.summary,
		Auth:    AuthSpec{Required: true, Kinds: []AuthKind{AuthPassword, AuthSSHKey}},
		// DefaultScheme left empty: SSH has no URL-scheme concept, same as
		// mysql/redis (D10).
		DefaultResolver: p.resolver,
	}
}

func (p osReleaseFamilyProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	const cmd = "cat /etc/os-release"
	out, verified, err := sshRunCommand(ctx, t, cmd)
	if err != nil {
		if isSSHExitError(err) {
			return obs, fmt.Errorf("%w: %q: no such file (this isn't a systemd-based Linux, or not %s): %w", ErrNotSupported, cmd, p.product, err)
		}
		return obs, err
	}

	fields := parseOSRelease(out)
	if !p.match(fields) {
		return obs, fmt.Errorf("%w: /etc/os-release reports ID=%q, not %s", ErrNotSupported, fields["ID"], p.product)
	}

	version, ok := fields["VERSION_ID"]
	if !ok {
		return obs, fmt.Errorf("%w: /etc/os-release has no VERSION_ID field", ErrUnparseable)
	}

	obs.Version = version
	obs.Endpoint = "/etc/os-release"
	obs.Extra = map[string]string{"hostKeyVerified": strconv.FormatBool(verified)}
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}

// parseOSRelease parses the shell-variable-assignment shape /etc/os-release
// uses (per the systemd spec): KEY=VALUE lines, VALUE optionally
// double-quoted. Real files never need shell-quote escaping beyond that
// (verified across every fixture this family is tested against), so this
// does not attempt a full shell-quoting parser.
func parseOSRelease(raw string) map[string]string {
	fields := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		fields[key] = strings.Trim(val, `"'`)
	}
	return fields
}

// osReleaseIDEquals builds a match func for the common case: one product, one
// exact ID= value.
func osReleaseIDEquals(id string) func(map[string]string) bool {
	return func(f map[string]string) bool { return f["ID"] == id }
}
