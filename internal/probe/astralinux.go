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

// astraLinuxProbe identifies Astra Linux by SSHing in and reading
// /etc/astra_version — Astra's own identity file, not part of the
// osReleaseFamilyProbe family despite Astra also carrying an
// /etc/os-release (it's Debian-based: `ID_LIKE=debian`). Confirmed live
// (epicmorg/astralinux:1.7-main and :1.8-main) that /etc/os-release's own
// VERSION_ID is not usable for this: it reads "1.8_x86-64" — an
// architecture suffix baked into the version string itself, not a clean
// version. /etc/astra_version has none of that: it reads a plain "1.8.6"/
// "1.7.9", the real point-release Astra itself tracks.
//
// No DefaultResolver: endoflife.date has no Astra Linux calendar
// (confirmed 404 under astra / astralinux / astra-linux).
type astraLinuxProbe struct{}

func (astraLinuxProbe) Meta() Meta {
	return Meta{
		Product: "astra-linux",
		Summary: "Astra Linux",
		Auth:    AuthSpec{Required: true, Kinds: []AuthKind{AuthPassword, AuthSSHKey}},
		// DefaultScheme left empty: SSH has no URL-scheme concept (D10).
	}
}

var astraVersionPattern = regexp.MustCompile(`^\d+(?:\.\d+)+$`)

// astraProbeCommand also lists the binary packages Astra's own OVAL
// names (D46), in the same round trip. packagesCommand's `|| true`s keep
// the exit status 0 even without /etc/astra_version; that case is the
// empty version below.
var astraProbeCommand = "cat /etc/astra_version 2>/dev/null" + packagesCommand(packagesDpkgBinary)

func (astraLinuxProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	out, verified, err := sshRunCommand(ctx, t, astraProbeCommand)
	if err != nil {
		if isSSHExitError(err) {
			return obs, fmt.Errorf("%w: %w", ErrNotSupported, err)
		}
		return obs, err
	}

	astraVersion, _, _ := strings.Cut(out, unameMarker)
	version := strings.TrimSpace(astraVersion)
	if version == "" {
		return obs, fmt.Errorf("%w: no /etc/astra_version (not Astra Linux)", ErrNotSupported)
	}
	if !astraVersionPattern.MatchString(version) {
		return obs, fmt.Errorf("%w: /etc/astra_version contains %q, not a version number", ErrUnparseable, version)
	}

	obs.Version = version
	obs.Endpoint = "/etc/astra_version"
	obs.Extra = map[string]string{"hostKeyVerified": strconv.FormatBool(verified)}
	h := parsePackagesOutput(packagesDpkgBinary, out)
	h.extra(obs.Extra)
	obs.Packages = h.packages
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}
