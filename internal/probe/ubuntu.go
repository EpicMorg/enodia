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

// ubuntuVersionPattern extracts the leading dotted version from
// os-release's VERSION field.
var ubuntuVersionPattern = regexp.MustCompile(`^(\d+\.\d+(?:\.\d+)?)`)

// ubuntuProbe reads /etc/os-release over SSH.
//
// Not osReleaseFamilyProbe: confirmed live (14.04 through 24.10) that
// Ubuntu's own VERSION_ID deliberately never changes after a release ships
// ("22.04" stays "22.04" for that release's entire support life), even
// though Canonical keeps shipping point releases with new install media —
// "22.04.5 LTS (Jammy Jellyfish)" for a real, fully patched 22.04 host, not
// "22.04". That point release exists only in the VERSION (and PRETTY_NAME)
// field, e.g. `VERSION="22.04.5 LTS (Jammy Jellyfish)"` next to
// `VERSION_ID="22.04"` — and only for LTS releases that shipped more than
// one point release; a non-LTS release's VERSION carries no extra segment
// at all (confirmed live: `VERSION="24.10 (Oracular Oriole)"`, matching
// VERSION_ID exactly). This probe prefers VERSION's number over
// VERSION_ID whenever it's strictly more precise and shares the same
// major.minor prefix — the same "read the field that actually has the
// precision" reasoning debian.go uses for /etc/debian_version, just from a
// field in the same file instead of a second one.
type ubuntuProbe struct{}

func (ubuntuProbe) Meta() Meta {
	return Meta{
		Product: "ubuntu",
		Summary: "Ubuntu",
		Auth:    AuthSpec{Required: true, Kinds: []AuthKind{AuthPassword, AuthSSHKey}},
		// DefaultScheme left empty: SSH has no URL-scheme concept (D10).
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "ubuntu"},
	}
}

func (ubuntuProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	const cmd = "cat /etc/os-release"
	out, verified, err := sshRunCommand(ctx, t, cmd)
	if err != nil {
		if isSSHExitError(err) {
			return obs, fmt.Errorf("%w: %q: no such file (not Ubuntu, or an OS without this file): %w", ErrNotSupported, cmd, err)
		}
		return obs, err
	}

	fields := parseOSRelease(out)
	if fields["ID"] != "ubuntu" {
		return obs, fmt.Errorf("%w: /etc/os-release reports ID=%q, not ubuntu", ErrNotSupported, fields["ID"])
	}

	version := fields["VERSION_ID"]
	if version == "" {
		return obs, fmt.Errorf("%w: /etc/os-release has no VERSION_ID field", ErrUnparseable)
	}

	if m := ubuntuVersionPattern.FindStringSubmatch(fields["VERSION"]); m != nil && strings.HasPrefix(m[1], version+".") {
		version = m[1]
	}

	obs.Version = version
	obs.Endpoint = "/etc/os-release"
	obs.Extra = map[string]string{"hostKeyVerified": strconv.FormatBool(verified)}
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}
