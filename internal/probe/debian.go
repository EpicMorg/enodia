// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/EpicMorg/enodia/internal/version"
)

// debianVersionMarker separates the two files' output in debianProbe's one
// combined SSH command — arbitrary but distinctive enough it will never
// collide with real file content.
const debianVersionMarker = "===ENODIA-DEBIAN-VERSION==="

// debianKernelMarker and debianPackagesMarker separate the running
// kernel's `uname -v` and dpkg-query's package list, the same way.
const (
	debianKernelMarker   = "===ENODIA-DEBIAN-KERNEL==="
	debianPackagesMarker = "===ENODIA-DEBIAN-PACKAGES==="
)

// debianProbeCommand is the one round trip debianProbe makes. Every part
// after os-release ends in `|| true` for the reason Probe explains.
//
// dpkg-query's source:Package/source:Version, not Package/Version: the
// Debian Security Tracker is indexed by source package and its fixed
// versions are source versions — confirmed live, binary acl
// 2.3.2-2+b1 (a binNMU) is source acl 2.3.2-2.
const debianProbeCommand = "cat /etc/os-release; echo '" + debianVersionMarker + "'; cat /etc/debian_version 2>/dev/null || true" +
	"; echo '" + debianKernelMarker + "'; uname -v 2>/dev/null || true" +
	"; echo '" + debianPackagesMarker + "'; dpkg-query -W -f='${db:Status-Abbrev}\\t${source:Package}\\t${source:Version}\\n' 2>/dev/null || true"

// debianKernelPattern pulls the kernel package's own Debian version out of
// `uname -v` — confirmed live: "#1 SMP PREEMPT_DYNAMIC Debian 6.12.107-1
// (2026-08-29)". `uname -r` ("6.12.107+deb13-amd64") is the ABI name, not
// a version the tracker's fixed versions can be compared with.
var debianKernelPattern = regexp.MustCompile(`\bDebian (\d[\w.+~:-]*)`)

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

	// The trailing `|| true`s matter: a target with no /etc/debian_version
	// or no dpkg-query at all (shouldn't happen on real Debian, but this
	// must not turn into a connection-level failure if it ever does) must
	// not make the whole command exit non-zero, which sshRunCommand would
	// otherwise surface as ErrNotSupported before this probe ever gets to
	// look at os-release.
	out, verified, err := sshRunCommand(ctx, t, debianProbeCommand)
	if err != nil {
		return obs, err
	}

	osRelease, rest, _ := strings.Cut(out, debianVersionMarker)
	debianVersionOut, rest, _ := strings.Cut(rest, debianKernelMarker)
	kernelOut, packagesOut, _ := strings.Cut(rest, debianPackagesMarker)
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

	if codename := fields["VERSION_CODENAME"]; codename != "" {
		obs.Extra["codename"] = codename
	}
	if m := debianKernelPattern.FindStringSubmatch(kernelOut); m != nil {
		obs.Extra["kernel"] = m[1]
	}
	obs.Packages = parseDpkgSourcePackages(packagesOut)

	obs.Version = version
	obs.Endpoint = "/etc/os-release"
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}

// parseDpkgSourcePackages reads debianProbeCommand's dpkg-query lines
// ("<status>\t<source>\t<source version>") into source package ->
// version, keeping only installed packages: the second status letter is
// dpkg's current state, and "i" (installed), "W"/"t" (installed, triggers
// pending) are the ones whose files are on disk. "rc" — removed, config
// files left behind — is confirmed live as the common other case (51 of
// 1970 on a real trixie host). When one source package is installed at
// more than one version (old linux-headers next to new ones, a partial
// upgrade), the oldest wins: that's the one still missing a fix. Nil when
// nothing parsed, so an old inventory and a host without dpkg-query look
// the same.
func parseDpkgSourcePackages(out string) map[string]string {
	var pkgs map[string]string
	for line := range strings.Lines(out) {
		fields := strings.Split(strings.TrimRight(line, "\r\n"), "\t")
		if len(fields) != 3 || len(fields[0]) < 2 || !strings.ContainsRune("iWt", rune(fields[0][1])) {
			continue
		}
		name, ver := fields[1], fields[2]
		if name == "" || ver == "" {
			continue
		}
		if pkgs == nil {
			pkgs = map[string]string{}
		}
		if have, ok := pkgs[name]; !ok || version.CompareDebian(ver, have) < 0 {
			pkgs[name] = ver
		}
	}
	return pkgs
}
