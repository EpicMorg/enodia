// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"fmt"
	"sort"
	"strings"
)

// builtin is the complete list of compiled-in probes.
//
// Registration is explicit rather than via init(): this slice is meant to read
// as a table of contents, and a pull request adding a product should be
// visible here. Ordering is alphabetical by product.
var builtin = []Probe{
	// almalinux 9 (docker.io/almalinux:9): ID="almalinux", VERSION_ID="9.8".
	osReleaseFamilyProbe{product: "almalinux", summary: "AlmaLinux", resolver: ResolverRef{Type: "endoflife", ID: "almalinux"}, match: osReleaseIDEquals("almalinux")},
	// alpine:latest: ID=alpine, VERSION_ID=3.24.1.
	osReleaseFamilyProbe{product: "alpine-linux", summary: "Alpine Linux", resolver: ResolverRef{Type: "endoflife", ID: "alpine-linux"}, match: osReleaseIDEquals("alpine")},
	// amazonlinux:2023: ID="amzn", VERSION_ID="2023".
	osReleaseFamilyProbe{product: "amazon-linux", summary: "Amazon Linux", resolver: ResolverRef{Type: "endoflife", ID: "amazon-linux"}, match: osReleaseIDEquals("amzn")},
	apacheProbe{},
	artifactoryProbe{},
	// epicmorg/astralinux:1.7-main / :1.8-main: /etc/astra_version -> "1.7.9" / "1.8.6".
	astraLinuxProbe{},
	&atlassianProbe{product: "bamboo", typeID: "bamboo", resolver: "bamboo", summary: "Atlassian Bamboo (Data Center)"},
	&atlassianProbe{product: "bitbucket", typeID: "stash", resolver: "bitbucket", summary: "Atlassian Bitbucket (Data Center)"},
	bitwardenFamilyProbe{product: "bitwarden", summary: "Bitwarden (self-hosted)", resolver: ResolverRef{Type: "github", ID: "bitwarden/server"}},
	// Legacy, EOL CentOS Linux (5/6/7/8) via /etc/redhat-release — real
	// fleets still run these even though the product is dead. Not part of
	// osReleaseFamilyProbe: confirmed live that centos:5 and :6 predate
	// the os-release convention entirely (no such file at all).
	centosProbe{},
	// quay.io/centos/centos:stream9: ID="centos" (same as legacy, EOL CentOS
	// Linux), NAME="CentOS Stream" — the field that actually tells them apart.
	osReleaseFamilyProbe{product: "centos-stream", summary: "CentOS Stream", resolver: ResolverRef{Type: "endoflife", ID: "centos-stream"}, match: func(f map[string]string) bool {
		return f["ID"] == "centos" && f["NAME"] == "CentOS Stream"
	}},
	clickhouseProbe{},
	&atlassianProbe{product: "confluence", typeID: "confluence", resolver: "confluence", summary: "Atlassian Confluence (Data Center)"},
	// debian:bookworm-slim: ID=debian, VERSION_ID="12".
	osReleaseFamilyProbe{product: "debian", summary: "Debian", resolver: ResolverRef{Type: "endoflife", ID: "debian"}, match: osReleaseIDEquals("debian")},
	elasticsearchProbe{},
	esxiProbe{},
	// Real ISO rootfs capture (not a Docker image — none exists): ID="eurolinux", VERSION_ID="8.10".
	osReleaseFamilyProbe{product: "eurolinux", summary: "EuroLinux", resolver: ResolverRef{Type: "endoflife", ID: "eurolinux"}, match: osReleaseIDEquals("eurolinux")},
	// fedora:latest: ID=fedora, VERSION_ID=44.
	osReleaseFamilyProbe{product: "fedora", summary: "Fedora Linux", resolver: ResolverRef{Type: "endoflife", ID: "fedora"}, match: osReleaseIDEquals("fedora")},
	forgejoProbe{},
	// FreeBSD generates /var/run/os-release itself at boot, in the same
	// KEY=VALUE shape Linux distros ship statically at /etc/os-release.
	// Verified live via QEMU (FreeBSD's own official cloud qcow2, no Docker
	// image exists): ID=freebsd, VERSION_ID="15.1".
	osReleaseFamilyProbe{product: "freebsd", summary: "FreeBSD", resolver: ResolverRef{Type: "endoflife", ID: "freebsd"}, match: osReleaseIDEquals("freebsd"), path: "/var/run/os-release"},
	genericProbe{},
	// gentoo/stage3 (official gentoo.org image): ID=gentoo, VERSION_ID=2.18
	// — Gentoo Base System's own release number, not a distro version in
	// the traditional sense (Gentoo is rolling-release; no endoflife.date
	// calendar exists, confirmed 404, for the same reason).
	osReleaseFamilyProbe{product: "gentoo", summary: "Gentoo Linux", match: osReleaseIDEquals("gentoo")},
	gitlabProbe{},
	grafanaProbe{},
	graylogProbe{},
	haproxyProbe{},
	harborProbe{},
	jaegerProbe{},
	jellyfinProbe{},
	jenkinsProbe{},
	&atlassianProbe{product: "jira", typeID: "jira", resolver: "jira-software", summary: "Atlassian Jira (Data Center)"},
	// kalilinux/kali-rolling: ID=kali, VERSION_ID="2026.3" — a dated
	// rolling-release snapshot, not a discrete version; no endoflife.date
	// calendar exists for the same reason (confirmed 404).
	osReleaseFamilyProbe{product: "kali-linux", summary: "Kali Linux", match: osReleaseIDEquals("kali")},
	keycloakProbe{},
	kibanaProbe{},
	zouFamilyProbe{product: "kitsu", summary: "Kitsu (CG-Wire / Zou frontend)", resolver: ResolverRef{Type: "github", ID: "cgwire/kitsu"}},
	// Real ISO rootfs capture: ID=linuxmint, VERSION_ID="22.3" — unlike the
	// only Docker Hub image found earlier (linuxmintd/mint22-amd64, Mint's
	// own CI build chroot, which reports the underlying Ubuntu instead),
	// this is genuinely Mint's own identity.
	osReleaseFamilyProbe{product: "linuxmint", summary: "Linux Mint", resolver: ResolverRef{Type: "endoflife", ID: "linuxmint"}, match: osReleaseIDEquals("linuxmint")},
	logstashProbe{},
	// Verified live via sw_vers over SSH against a real Mac (macOS 15.4).
	macosProbe{},
	mattermostProbe{},
	mongodbProbe{},
	mysqlProbe{},
	// Captured via vmactions/netbsd-vm (see uname.go): `uname -sr` -> "NetBSD 11.0".
	unameFamilyProbe{product: "netbsd", summary: "NetBSD", resolver: ResolverRef{Type: "endoflife", ID: "netbsd"}, unameName: "NetBSD"},
	nextcloudProbe{},
	nexusProbe{},
	nginxProbe{},
	// Real ISO rootfs capture (the only Docker Hub image, nixos/nix, is
	// just the Nix package manager on a non-NixOS base with no
	// os-release at all — confirmed live, see DECISIONS.md D23):
	// ID=nixos, VERSION_ID="26.05".
	osReleaseFamilyProbe{product: "nixos", summary: "NixOS", resolver: ResolverRef{Type: "endoflife", ID: "nixos"}, match: osReleaseIDEquals("nixos")},
	oauth2ProxyProbe{},
	// Captured via vmactions/openbsd-vm (see uname.go): `uname -sr` -> "OpenBSD 7.9".
	unameFamilyProbe{product: "openbsd", summary: "OpenBSD", resolver: ResolverRef{Type: "endoflife", ID: "openbsd"}, unameName: "OpenBSD"},
	// Captured via vmactions/openeuler-vm (24.03-LTS-SP4, the action's
	// default release): ID="openEuler" (capital E, confirmed live — not
	// lowercase), VERSION_ID="24.03".
	osReleaseFamilyProbe{product: "openeuler", summary: "openEuler", match: osReleaseIDEquals("openEuler")},
	opensearchProbe{},
	// opensuse/leap:latest: ID="opensuse-leap", VERSION_ID="16.0". Tumbleweed
	// (ID="opensuse-tumbleweed") isn't covered by a real fixture here but
	// shares the "opensuse-" prefix, so it's accepted by the same product
	// rather than left unmatched.
	osReleaseFamilyProbe{product: "opensuse", summary: "openSUSE", resolver: ResolverRef{Type: "endoflife", ID: "opensuse"}, match: func(f map[string]string) bool {
		return strings.HasPrefix(f["ID"], "opensuse")
	}},
	// Captured via vmactions/opnsense-vm (see opnsense.go): `opnsense-version`
	// -> "OPNsense 26.7 (amd64)".
	opnsenseProbe{},
	// oraclelinux:9: ID="ol", VERSION_ID="9.8".
	osReleaseFamilyProbe{product: "oracle-linux", summary: "Oracle Linux", resolver: ResolverRef{Type: "endoflife", ID: "oracle-linux"}, match: osReleaseIDEquals("ol")},
	// Captured via vmactions/solaris-vm (see solaris.go): /etc/release's
	// "Oracle Solaris 11.4 X86" line.
	oracleSolarisProbe{},
	owncastProbe{},
	perforceSwarmProbe{},
	pgadminProbe{},
	// Official top-level photon:5.0 (Docker's Official Images program,
	// not vmware/photon's own stale repo which stops at 2.0): ID=photon,
	// VERSION_ID=5.0.
	osReleaseFamilyProbe{product: "photon", summary: "VMware Photon OS", resolver: ResolverRef{Type: "endoflife", ID: "photon"}, match: osReleaseIDEquals("photon")},
	phpmyadminProbe{},
	portainerProbe{},
	postgresExporterProbe{},
	postgresProbe{},
	// Real ISO rootfs capture: ID="postmarketos", VERSION_ID="v26.06" — the
	// leading "v" is the vendor's own format; internal/version.Core already
	// strips a leading v/V before comparison, same as it does for GitHub's
	// "v1.2.3" tags, so this is passed through as-is rather than trimmed
	// here.
	osReleaseFamilyProbe{product: "postmarketos", summary: "postmarketOS", resolver: ResolverRef{Type: "endoflife", ID: "postmarketos"}, match: osReleaseIDEquals("postmarketos")},
	proftpdProbe{},
	// GET /api2/json/version, authenticated with an API token. Verified
	// live against a real Proxmox VE 9.2.2 host.
	proxmoxProbe{},
	redisProbe{},
	// alrdockerhub/redos:7.3.1 (real RED OS content: HOME_URL/BUG_REPORT_URL
	// point at red-soft.ru): ID="redos", VERSION_ID="7.3.1".
	osReleaseFamilyProbe{product: "redos", summary: "RED OS", match: osReleaseIDEquals("redos")},
	// registry.redhat.io/ubi9 (Red Hat's own free Universal Base Image):
	// ID=rhel, VERSION_ID="9.8".
	osReleaseFamilyProbe{product: "rhel", summary: "Red Hat Enterprise Linux", resolver: ResolverRef{Type: "endoflife", ID: "rhel"}, match: osReleaseIDEquals("rhel")},
	// rockylinux:9: ID="rocky", VERSION_ID="9.3".
	osReleaseFamilyProbe{product: "rocky-linux", summary: "Rocky Linux", resolver: ResolverRef{Type: "endoflife", ID: "rocky-linux"}, match: osReleaseIDEquals("rocky")},
	routerosProbe{},
	// vbatts/slackware:14.2: ID=slackware, VERSION_ID=14.2 — it does ship
	// /etc/os-release, despite historical docs saying it doesn't.
	osReleaseFamilyProbe{product: "slackware", summary: "Slackware", resolver: ResolverRef{Type: "endoflife", ID: "slackware"}, match: osReleaseIDEquals("slackware")},
	sonarqubeProbe{},
	sshProbe{},
	// Real ISO rootfs capture — SteamOS 2 (Debian-based "brewmaster"):
	// ID=steamos, VERSION_ID="2". SteamOS 3.x (Arch-based, current Steam
	// Deck "holo") is expected to share the same ID field (per the
	// vendor's own consistent branding) but hasn't been captured live —
	// only the 2.x fixture below is confirmed.
	osReleaseFamilyProbe{product: "steamos", summary: "SteamOS", resolver: ResolverRef{Type: "endoflife", ID: "steamos"}, match: osReleaseIDEquals("steamos")},
	teamcityProbe{},
	testrailProbe{},
	traefikProbe{},
	// GET /api/v2.0/system/info, authenticated with an API key as a plain
	// bearer token. Verified live against a real TrueNAS 25.10.7 host —
	// superseded an earlier SSH-based (/etc/version) version once this
	// became available (D2: one product, one probe, not both at once).
	truenasProbe{},
	// ubuntu:24.04: ID=ubuntu, VERSION_ID="24.04".
	osReleaseFamilyProbe{product: "ubuntu", summary: "Ubuntu", resolver: ResolverRef{Type: "endoflife", ID: "ubuntu"}, match: osReleaseIDEquals("ubuntu")},
	vaultProbe{},
	bitwardenFamilyProbe{product: "vaultwarden", summary: "Vaultwarden", resolver: ResolverRef{Type: "github", ID: "dani-garcia/vaultwarden"}},
	vcenterProbe{},
	wordpressProbe{},
	youtrackProbe{},
	zabbixProbe{},
	zouFamilyProbe{product: "zou", summary: "Zou (CG-Wire API backend)"},
}

var byProduct = func() map[string]Probe {
	m := make(map[string]Probe, len(builtin))
	for _, p := range builtin {
		meta := p.Meta()
		if _, dup := m[meta.Product]; dup {
			panic("enodia: duplicate probe product " + meta.Product)
		}
		m[meta.Product] = p
		for _, a := range meta.Aliases {
			if _, dup := m[a]; dup {
				panic("enodia: probe alias collides with a product: " + a)
			}
			m[a] = p
		}
	}
	return m
}()

// Get returns the probe for a product id.
func Get(product string) (Probe, error) {
	p, ok := byProduct[product]
	if !ok {
		return nil, fmt.Errorf("unknown product %q; run `enodia products` to list what is supported", product)
	}
	return p, nil
}

// Products lists every supported product id, sorted.
func Products() []string {
	out := make([]string, 0, len(builtin))
	for _, p := range builtin {
		out = append(out, p.Meta().Product)
	}
	sort.Strings(out)
	return out
}

// All returns every registered probe, in registry order.
func All() []Probe { return append([]Probe(nil), builtin...) }
