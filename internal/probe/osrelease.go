// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// osReleaseFamilyProbe identifies an OS by SSHing in and reading its
// os-release file — the systemd-standardized identity format present on
// every registration in this family. Confirmed live, one real system per
// registration (see registry.go's comment next to each entry for exactly
// what it reported): debian, ubuntu, fedora, a real Red Hat UBI9 image for
// rhel, rockylinux, almalinux, oraclelinux, amazonlinux, opensuse/leap,
// alpine, a real CentOS Stream 9 image, vbatts/slackware (Slackware 14.2,
// which turned out to ship os-release too, not just the
// historically-documented /etc/slackware-version) — and, at a different
// path, FreeBSD: verified live against a real FreeBSD 15.1 VM (no Docker
// image exists; booted from FreeBSD's own official cloud qcow2 under QEMU)
// that it generates /var/run/os-release itself, dynamically at boot
// (`/etc/rc.d/os-release`), in the exact same KEY=VALUE shape Linux distros
// ship statically at /etc/os-release — including a real ID=freebsd and
// VERSION_ID.
//
// D9 (product declared explicitly, probe verifies): most are a plain ID==
// check, but two needed more — see match's doc on each registration.
type osReleaseFamilyProbe struct {
	product  string
	summary  string
	resolver ResolverRef
	match    func(fields map[string]string) bool
	// path is the os-release file to read; empty means the systemd-standard
	// /etc/os-release. FreeBSD is the one registration that overrides this
	// (/var/run/os-release — see above).
	path string
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

	path := p.path
	if path == "" {
		path = "/etc/os-release"
	}
	cmd := "cat " + path
	out, verified, err := sshRunCommand(ctx, t, cmd)
	if err != nil {
		if isSSHExitError(err) {
			return obs, fmt.Errorf("%w: %q: no such file (not %s, or an OS without this file): %w", ErrNotSupported, cmd, p.product, err)
		}
		return obs, err
	}

	fields := parseOSRelease(out)
	if !p.match(fields) {
		return obs, fmt.Errorf("%w: %s reports ID=%q, not %s", ErrNotSupported, path, fields["ID"], p.product)
	}

	version, ok := fields["VERSION_ID"]
	if !ok {
		return obs, fmt.Errorf("%w: %s has no VERSION_ID field", ErrUnparseable, path)
	}

	obs.Version = version
	obs.Endpoint = path
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
