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

// debianVersionMarker separates the two files' output in debianProbe's one
// combined SSH command — arbitrary but distinctive enough it will never
// collide with real file content.
const debianVersionMarker = "===ENODIA-DEBIAN-VERSION==="

// debianVersionPattern matches a real point release ("13.6", "12.15"), the
// only shape /etc/debian_version is trusted for. Debian testing/unstable's
// own copy reads "<codename>/sid" (confirmed live: debian:testing gives
// "forky/sid", with no VERSION_ID in os-release at all — there's no
// numbered release yet, and this probe doesn't invent one), which this
// pattern correctly rejects.
var debianVersionPattern = regexp.MustCompile(`^\d+(?:\.\d+)*$`)

// debianProbe reads /etc/os-release and /etc/debian_version over SSH, in
// one round trip.
//
// Confirmed live: Debian's own /etc/os-release VERSION_ID never carries a
// point release — a fully patched Debian 13 stable install still reports
// bare VERSION_ID="13", the same as a day-one install, since Debian doesn't
// treat a point release as a distinct VERSION_ID the way RHEL-family
// distros do. The actual point release ("13.6") lives only in
// /etc/debian_version.
//
// That file isn't Debian-exclusive, though, and its content can't be
// trusted without checking os-release first: confirmed live that a real
// Ubuntu 24.04 image also ships /etc/debian_version, inherited from its
// build lineage, reading "trixie/sid" — meaningless for Ubuntu's own
// version, and exactly the kind of trap D9 warns about. This probe checks
// os-release's ID=debian before ever looking at debian_version's content.
//
// (A real debian:trixie image was also found, live, to carry a
// DEBIAN_VERSION_FULL="13.6" field directly in /etc/os-release — absent
// from bookworm's. Not used here: /etc/debian_version already gives the
// identical value and covers every Debian release uniformly, old and new,
// with no dependency on a field this project can't confirm is stable or
// documented upstream.)
type debianProbe struct{}

func (debianProbe) Meta() Meta {
	return Meta{
		Product: "debian",
		Summary: "Debian",
		Auth:    AuthSpec{Required: true, Kinds: []AuthKind{AuthPassword, AuthSSHKey}},
		// DefaultScheme left empty: SSH has no URL-scheme concept (D10).
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "debian"},
	}
}

func (debianProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	// The trailing `|| true` matters: a target with no /etc/debian_version
	// at all (shouldn't happen on real Debian, but this must not turn into
	// a connection-level failure if it ever does) must not make the whole
	// command exit non-zero, which sshRunCommand would otherwise surface as
	// ErrNotSupported before this probe ever gets to look at os-release.
	cmd := "cat /etc/os-release; echo '" + debianVersionMarker + "'; cat /etc/debian_version 2>/dev/null || true"
	out, verified, err := sshRunCommand(ctx, t, cmd)
	if err != nil {
		return obs, err
	}

	osRelease, debianVersionOut, _ := strings.Cut(out, debianVersionMarker)
	fields := parseOSRelease(osRelease)
	if fields["ID"] != "debian" {
		return obs, fmt.Errorf("%w: /etc/os-release reports ID=%q, not debian", ErrNotSupported, fields["ID"])
	}

	version := fields["VERSION_ID"]
	if version == "" {
		return obs, fmt.Errorf("%w: /etc/os-release has no VERSION_ID field", ErrUnparseable)
	}

	obs.Extra = map[string]string{"hostKeyVerified": strconv.FormatBool(verified)}
	debianVersion := strings.TrimSpace(debianVersionOut)
	if debianVersion != "" {
		obs.Extra["debianVersion"] = debianVersion
		if debianVersionPattern.MatchString(debianVersion) {
			version = debianVersion
		}
	}

	obs.Version = version
	obs.Endpoint = "/etc/os-release"
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}
