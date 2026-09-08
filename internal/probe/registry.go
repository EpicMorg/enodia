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
	&atlassianProbe{product: "bamboo", typeID: "bamboo", resolver: "bamboo", summary: "Atlassian Bamboo (Data Center)"},
	&atlassianProbe{product: "bitbucket", typeID: "stash", resolver: "bitbucket", summary: "Atlassian Bitbucket (Data Center)"},
	bitwardenFamilyProbe{product: "bitwarden", summary: "Bitwarden (self-hosted)", resolver: ResolverRef{Type: "github", ID: "bitwarden/server"}},
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
	// fedora:latest: ID=fedora, VERSION_ID=44.
	osReleaseFamilyProbe{product: "fedora", summary: "Fedora Linux", resolver: ResolverRef{Type: "endoflife", ID: "fedora"}, match: osReleaseIDEquals("fedora")},
	forgejoProbe{},
	// FreeBSD generates /var/run/os-release itself at boot, in the same
	// KEY=VALUE shape Linux distros ship statically at /etc/os-release.
	// Verified live via QEMU (FreeBSD's own official cloud qcow2, no Docker
	// image exists): ID=freebsd, VERSION_ID="15.1".
	osReleaseFamilyProbe{product: "freebsd", summary: "FreeBSD", resolver: ResolverRef{Type: "endoflife", ID: "freebsd"}, match: osReleaseIDEquals("freebsd"), path: "/var/run/os-release"},
	genericProbe{},
	gitlabProbe{},
	grafanaProbe{},
	graylogProbe{},
	haproxyProbe{},
	harborProbe{},
	jaegerProbe{},
	jellyfinProbe{},
	jenkinsProbe{},
	&atlassianProbe{product: "jira", typeID: "jira", resolver: "jira-software", summary: "Atlassian Jira (Data Center)"},
	keycloakProbe{},
	kibanaProbe{},
	zouFamilyProbe{product: "kitsu", summary: "Kitsu (CG-Wire / Zou frontend)", resolver: ResolverRef{Type: "github", ID: "cgwire/kitsu"}},
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
	oauth2ProxyProbe{},
	// Captured via vmactions/openbsd-vm (see uname.go): `uname -sr` -> "OpenBSD 7.9".
	unameFamilyProbe{product: "openbsd", summary: "OpenBSD", resolver: ResolverRef{Type: "endoflife", ID: "openbsd"}, unameName: "OpenBSD"},
	opensearchProbe{},
	// opensuse/leap:latest: ID="opensuse-leap", VERSION_ID="16.0". Tumbleweed
	// (ID="opensuse-tumbleweed") isn't covered by a real fixture here but
	// shares the "opensuse-" prefix, so it's accepted by the same product
	// rather than left unmatched.
	osReleaseFamilyProbe{product: "opensuse", summary: "openSUSE", resolver: ResolverRef{Type: "endoflife", ID: "opensuse"}, match: func(f map[string]string) bool {
		return strings.HasPrefix(f["ID"], "opensuse")
	}},
	// oraclelinux:9: ID="ol", VERSION_ID="9.8".
	osReleaseFamilyProbe{product: "oracle-linux", summary: "Oracle Linux", resolver: ResolverRef{Type: "endoflife", ID: "oracle-linux"}, match: osReleaseIDEquals("ol")},
	// Captured via vmactions/solaris-vm (see solaris.go): /etc/release's
	// "Oracle Solaris 11.4 X86" line.
	oracleSolarisProbe{},
	owncastProbe{},
	perforceSwarmProbe{},
	pgadminProbe{},
	phpmyadminProbe{},
	portainerProbe{},
	postgresExporterProbe{},
	postgresProbe{},
	proftpdProbe{},
	redisProbe{},
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
	teamcityProbe{},
	testrailProbe{},
	traefikProbe{},
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
