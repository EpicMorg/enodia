// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// oracleSolarisProbe identifies Oracle Solaris by SSHing in and reading
// /etc/release — its own long-standing identity file, predating and
// unrelated to the Linux systemd os-release convention. `uname -sr` on
// Solaris only gives the SunOS kernel version ("SunOS 5.11" for every
// Solaris 11.x release, since SunOS versioning is decoupled from the
// product version), so it can't tell 11.3 from 11.4 the way /etc/release's
// own "Oracle Solaris 11.4 X86" line does.
//
// Verified live against a real Oracle Solaris 11.4 instance — no
// downloadable image is obtainable without an Oracle account/OTN license
// (see DECISIONS.md D23), so this was captured via vmactions' GitHub Action
// (github.com/vmactions/solaris-vm), which builds and republishes Oracle's
// own free-to-redistribute Solaris 11.4 CBE (Common Build Environment,
// meant for exactly this kind of CI use) rather than anything obtained by
// working around Oracle's own licensing.
type oracleSolarisProbe struct{}

func (oracleSolarisProbe) Meta() Meta {
	return Meta{
		Product: "oracle-solaris",
		Summary: "Oracle Solaris",
		Auth:    AuthSpec{Required: true, Kinds: []AuthKind{AuthPassword, AuthSSHKey}},
		// DefaultScheme left empty: SSH has no URL-scheme concept (D10).
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "oracle-solaris"},
	}
}

// oracleSolarisReleasePattern matches /etc/release's first line, e.g.
// "                             Oracle Solaris 11.4 X86" — confirmed live
// that real output is indented with no leading anchor, hence FindSubmatch
// rather than requiring the match at line start.
var oracleSolarisReleasePattern = regexp.MustCompile(`Oracle Solaris (\d+(?:\.\d+)*)`)

func (oracleSolarisProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	const cmd = "cat /etc/release"
	out, verified, err := sshRunCommand(ctx, t, cmd)
	if err != nil {
		if isSSHExitError(err) {
			return obs, fmt.Errorf("%w: %q: no such file (not Oracle Solaris): %w", ErrNotSupported, cmd, err)
		}
		return obs, err
	}

	m := oracleSolarisReleasePattern.FindStringSubmatch(out)
	if m == nil {
		return obs, fmt.Errorf("%w: /etc/release has no \"Oracle Solaris <version>\" line", ErrNotSupported)
	}

	obs.Version = m[1]
	obs.Endpoint = "/etc/release"
	obs.Extra = map[string]string{"hostKeyVerified": strconv.FormatBool(verified)}
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}
