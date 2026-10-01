// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// pfsenseProbe identifies pfSense Community Edition by SSHing in and
// reading /etc/version and /etc/platform in one round trip.
//
// Confirmed live against three real pfSense CE hosts (2.7.2-RELEASE,
// 2.8.1-RELEASE ×2): /etc/version holds exactly the version string pfSense's
// own dashboard shows, and /etc/platform reads "pfSense" on Community
// Edition. Netgate's commercial pfSense Plus is documented (not confirmed
// live here — no Plus instance was available to test against) to report
// "pfSense-Plus" in that same file and uses an entirely different,
// calendar-based version scheme ("24.11", not "2.7.2-RELEASE") — a
// different product with its own lifecycle, the same D9 split this project
// already made for vcenter/esxi and sonarqube-server/-community. Rather
// than guess at Plus's real shape, this probe explicitly rejects it instead
// of misreporting a CE-shaped observation for it.
//
// No DefaultResolver: endoflife.date has no pfsense/pfsense-ce/pfsense-plus
// page under any slug tried (confirmed 404) — inventory-only, the same as
// gentoo/kali-linux/perforce.
type pfsenseProbe struct{}

func (pfsenseProbe) Meta() Meta {
	return Meta{
		Product: "pfsense",
		Summary: "pfSense Community Edition",
		Auth:    AuthSpec{Required: true, Kinds: []AuthKind{AuthPassword, AuthSSHKey}},
		// DefaultScheme left empty: SSH has no URL-scheme concept (D10).
	}
}

const pfsenseVersionMarker = "===ENODIA-PFSENSE-PLATFORM==="

func (pfsenseProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	cmd := "cat /etc/version; echo '" + pfsenseVersionMarker + "'; cat /etc/platform"
	out, verified, err := sshRunCommand(ctx, t, cmd)
	if err != nil {
		if isSSHExitError(err) {
			return obs, fmt.Errorf("%w: %q: no such file (not pfSense): %w", ErrNotSupported, cmd, err)
		}
		return obs, err
	}

	version, platform, ok := strings.Cut(out, pfsenseVersionMarker)
	if !ok {
		return obs, fmt.Errorf("%w: unexpected output from %q", ErrUnparseable, cmd)
	}
	version = strings.TrimSpace(version)
	platform = strings.TrimSpace(platform)

	switch platform {
	case "pfSense":
		// Community Edition — the only shape this probe reports.
	case "pfSense-Plus":
		return obs, fmt.Errorf("%w: this is pfSense Plus (a different Netgate product, its own version scheme) — no probe for it yet", ErrNotSupported)
	default:
		return obs, fmt.Errorf("%w: /etc/platform reads %q, not \"pfSense\"", ErrNotSupported, platform)
	}
	if version == "" {
		return obs, fmt.Errorf("%w: /etc/version was empty", ErrUnparseable)
	}

	obs.Version = version
	obs.Endpoint = "/etc/version"
	obs.Extra = map[string]string{"hostKeyVerified": strconv.FormatBool(verified)}
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}
