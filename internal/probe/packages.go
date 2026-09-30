// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"strings"

	"github.com/EpicMorg/enodia/internal/version"
)

// packageKind says which package manager an OS probe also lists
// installed packages from, for package-level CVE matching (D42, D43).
type packageKind int

const (
	packagesNone packageKind = iota
	// packagesDpkgBinary lists binary packages: what Ubuntu's OVAL names.
	// (debianProbe lists source packages instead — the Debian Security
	// Tracker's key — with its own command.)
	packagesDpkgBinary
	// packagesRPM lists binary packages with their AppStream module
	// stream: what RHEL-family OVAL names.
	packagesRPM
)

// Section markers for the package-collecting half of an OS probe's one
// SSH command.
const (
	unameMarker    = "===ENODIA-UNAME==="
	packagesMarker = "===ENODIA-PACKAGES==="
)

// packagesCommand is appended to an OS probe's own command. Every part
// ends in `|| true`: a host without uname or the package tool must still
// be identified by its os-release, just with no packages.
//
// uname -r, -m and -v, one per line: -r is the running kernel (for rpm,
// its version-release; for Ubuntu, the ABI and flavour its OVAL matches
// on), -m the architecture (Oracle Linux's OVAL has separate x86_64 and
// aarch64 branches), -v Ubuntu's upload number (see
// cve.ubuntuKernelVersion).
//
// rpm's MODULARITYLABEL needs rpm 4.14+ (RHEL 8+); an older rpm rejects
// the whole query over the unknown tag, so it's retried without it.
func packagesCommand(kind packageKind) string {
	uname := "; echo '" + unameMarker + "'; uname -r 2>/dev/null || echo; uname -m 2>/dev/null || echo; uname -v 2>/dev/null || echo"
	switch kind {
	case packagesDpkgBinary:
		return uname + "; echo '" + packagesMarker + "'; dpkg-query -W -f='${db:Status-Abbrev}\\t${Package}\\t${Version}\\n' 2>/dev/null || true"
	case packagesRPM:
		const qf = `%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}`
		return uname + "; echo '" + packagesMarker + "'; rpm -qa --qf '" + qf + `\t%{MODULARITYLABEL}\n' 2>/dev/null || rpm -qa --qf '` + qf + `\n' 2>/dev/null || true`
	}
	return ""
}

// hostPackages is what packagesCommand's output parses into.
type hostPackages struct {
	kernelRelease, arch, kernelVersion string
	packages, modules                  map[string]string
}

// parsePackagesOutput splits the output after an OS probe's own part
// (everything from unameMarker on) into its facts. Absent sections — an
// old fixture, a host without the tools — give zero values.
func parsePackagesOutput(kind packageKind, out string) hostPackages {
	var h hostPackages
	_, rest, ok := strings.Cut(out, unameMarker)
	if !ok {
		return h
	}
	unameOut, pkgOut, _ := strings.Cut(rest, packagesMarker)
	lines := strings.Split(strings.Trim(unameOut, "\r\n"), "\n")
	for i, dst := range []*string{&h.kernelRelease, &h.arch, &h.kernelVersion} {
		if i < len(lines) {
			*dst = strings.TrimSpace(lines[i])
		}
	}
	switch kind {
	case packagesDpkgBinary:
		h.packages = parseDpkgPackages(pkgOut)
	case packagesRPM:
		h.packages, h.modules = parseRPMPackages(pkgOut, h.kernelRelease, h.arch)
	}
	return h
}

// extra is h's single-valued facts as Observation.Extra keys.
func (h hostPackages) extra(into map[string]string) {
	for k, v := range map[string]string{"kernelRelease": h.kernelRelease, "arch": h.arch, "kernelVersion": h.kernelVersion} {
		if v != "" {
			into[k] = v
		}
	}
}

// parseDpkgPackages reads "<status>\t<name>\t<version>" lines, keeping
// installed packages only (see parseDpkgSourcePackages for the status
// rule) and, for a name installed at several versions (multiarch
// leftovers), the oldest.
func parseDpkgPackages(out string) map[string]string {
	return parseDpkgSourcePackages(out)
}

// parseRPMPackages reads "<name>\t<epoch>:<version>-<release>[\t<modularity label>]"
// lines. rpm prints a missing epoch as "(none)", normalised to 0 (what
// the OVAL data writes). gpg-pubkey entries are rpm's imported signing
// keys, not packages.
//
// A name installed at several versions is normal for rpm's installonly
// packages (kernel, kernel-core, kernel-modules... — dnf keeps three by
// default): the one matching the running kernel (uname -r, minus its
// ".<arch>" suffix) wins, since that's the one exposed, and otherwise the
// oldest, the one still missing a fix.
func parseRPMPackages(out, kernelRelease, arch string) (pkgs, modules map[string]string) {
	running := strings.TrimSuffix(kernelRelease, "."+arch)
	isRunning := func(evr string) bool {
		_, vr, _ := strings.Cut(evr, ":")
		return running != "" && vr == running
	}
	for line := range strings.Lines(out) {
		fields := strings.Split(strings.TrimRight(line, "\r\n"), "\t")
		if len(fields) < 2 || fields[0] == "" || fields[0] == "gpg-pubkey" {
			continue
		}
		name := fields[0]
		evr := strings.Replace(fields[1], "(none):", "0:", 1)
		if !strings.Contains(evr, ":") || !strings.Contains(evr, "-") {
			continue
		}
		if pkgs == nil {
			pkgs = map[string]string{}
		}
		if have, ok := pkgs[name]; ok {
			switch {
			case isRunning(have):
				continue
			case !isRunning(evr) && version.CompareRPM(evr, have) >= 0:
				continue
			}
		}
		pkgs[name] = evr
		delete(modules, name)
		if len(fields) > 2 {
			// "nodejs:20:9030020230906102914:rhel9" -> "nodejs:20"
			if parts := strings.SplitN(fields[2], ":", 3); len(parts) >= 2 && fields[2] != "(none)" {
				if modules == nil {
					modules = map[string]string{}
				}
				modules[name] = parts[0] + ":" + parts[1]
			}
		}
	}
	return pkgs, modules
}
