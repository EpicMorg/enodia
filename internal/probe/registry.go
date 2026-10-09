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
	osReleaseFamilyProbe{product: "almalinux", summary: "AlmaLinux", resolver: ResolverRef{Type: "endoflife", ID: "almalinux"}, match: osReleaseIDEquals("almalinux"), packages: packagesRPM},
	// alpine:latest: ID=alpine, VERSION_ID=3.24.1.
	osReleaseFamilyProbe{product: "alpine-linux", summary: "Alpine Linux", resolver: ResolverRef{Type: "endoflife", ID: "alpine-linux"}, match: osReleaseIDEquals("alpine"), packages: packagesAPK},
	// amazonlinux:2023: ID="amzn", VERSION_ID="2023".
	osReleaseFamilyProbe{product: "amazon-linux", summary: "Amazon Linux", resolver: ResolverRef{Type: "endoflife", ID: "amazon-linux"}, match: osReleaseIDEquals("amzn")},
	apacheProbe{},
	artifactoryProbe{},
	// epicmorg/astralinux:1.7-main / :1.8-main: /etc/astra_version -> "1.7.9" / "1.8.6".
	astraLinuxProbe{},
	&atlassianProbe{product: "bamboo", typeID: "bamboo", resolver: "bamboo", summary: "Atlassian Bamboo (Data Center)"},
	&atlassianProbe{product: "bitbucket", typeID: "stash", resolver: "bitbucket", summary: "Atlassian Bitbucket (Data Center)"},
	bitwardenFamilyProbe{product: "bitwarden", summary: "Bitwarden (self-hosted)", resolver: ResolverRef{Type: "github", ID: "bitwarden/server"}},
	// CQL native protocol v4: STARTUP, optional SASL PLAIN, then
	// system.local release_version. Verified live against cassandra:3.11
	// (3.11.19) and cassandra:5.0 with PasswordAuthenticator (5.0.9).
	cassandraProbe{},
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
	// debianProbe, not osReleaseFamilyProbe: /etc/os-release's VERSION_ID
	// never carries Debian's point release ("13", not "13.6") — see
	// debian.go for why this needs its own file.
	debianProbe{},
	// Confirmed live: /redfish/v1 carries Oem.Dell, the Manager resource
	// itself carries none — see dellidrac.go for why this is 2 requests.
	dellIDRACProbe{},
	// <meta name="generator" content="Doxygen X"> on a generated docs site.
	// Verified against doxygen.nl's own manual (1.19.0).
	doxygenProbe{},
	elasticsearchProbe{},
	esxiProbe{},
	// Real ISO rootfs capture (not a Docker image — none exists): ID="eurolinux", VERSION_ID="8.10".
	osReleaseFamilyProbe{product: "eurolinux", summary: "EuroLinux", resolver: ResolverRef{Type: "endoflife", ID: "eurolinux"}, match: osReleaseIDEquals("eurolinux")},
	// ONLYOFFICE Docs' Euro-Office fork, its own release line. Verified
	// live: nextcloud/aio-eurooffice (9.3.1).
	onlyofficeFamilyProbe{product: "euro-office", summary: "Euro-Office Docs (ONLYOFFICE fork)", brand: "Euro-Office", resolver: ResolverRef{Type: "github", ID: "Euro-Office/DocumentServer"}},
	// fedora:latest: ID=fedora, VERSION_ID=44.
	osReleaseFamilyProbe{product: "fedora", summary: "Fedora Linux", resolver: ResolverRef{Type: "endoflife", ID: "fedora"}, match: osReleaseIDEquals("fedora")},
	forgejoProbe{},
	fortiosProbe{},
	// FreeBSD generates /var/run/os-release itself at boot, in the same
	// KEY=VALUE shape Linux distros ship statically at /etc/os-release.
	// Verified live via QEMU (FreeBSD's own official cloud qcow2, no Docker
	// image exists): ID=freebsd, VERSION_ID="15.1".
	osReleaseFamilyProbe{product: "freebsd", summary: "FreeBSD", resolver: ResolverRef{Type: "endoflife", ID: "freebsd"}, match: osReleaseIDEquals("freebsd"), path: "/var/run/os-release"},
	freeradiusProbe{},
	genericProbe{},
	// gentoo/stage3 (official gentoo.org image): ID=gentoo, VERSION_ID=2.18
	// — Gentoo Base System's own release number, not a distro version in
	// the traditional sense (Gentoo is rolling-release; no endoflife.date
	// calendar exists, confirmed 404, for the same reason).
	osReleaseFamilyProbe{product: "gentoo", summary: "Gentoo Linux", match: osReleaseIDEquals("gentoo")},
	// The anonymous Admin API /ghost/api/admin/site/ (major.minor only).
	// Verified live against ghost:6 (6.69).
	ghostProbe{},
	gitlabProbe{},
	// gsad's <envelope><version> on /gmp, even in its 401. Verified live on a
	// production Greenbone Community Edition (gsad 24.12.0).
	greenboneProbe{},
	// GET /api/config with a long-lived token. Verified live (2026.10.0).
	homeAssistantProbe{},
	grafanaProbe{},
	graylogProbe{},
	haproxyProbe{},
	harborProbe{},
	// iLO 4's own non-standard "HP RESTful" shape, not full Redfish — see
	// hpilo4.go. iLO 5 is untested and needs its own probe/product.
	hpILO4Probe{},
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
	osReleaseFamilyProbe{product: "linuxmint", summary: "Linux Mint", resolver: ResolverRef{Type: "endoflife", ID: "linuxmint"}, match: osReleaseIDEquals("linuxmint"), packages: packagesDpkgBinary},
	logstashProbe{},
	// Verified live via sw_vers over SSH against a real Mac (macOS 15.4).
	macosProbe{},
	// Same wire format mysqlProbe reads, minus the mask: readMySQLProtocolVersion
	// is shared, see mariadb.go for exactly what differs (mysql.go).
	mariadbProbe{},
	mattermostProbe{},
	// "version" over the text protocol. Verified live against memcached:1.6
	// (1.6.45).
	memcachedProbe{},
	// `minio --version` over SSH (optionally in a container). Verified live
	// against an in-house build, RELEASE_INHOUSE.2025-03-12T18-04-18Z.
	minioProbe{},
	mongodbProbe{},
	mysqlProbe{},
	// Captured via vmactions/netbsd-vm (see uname.go): `uname -sr` -> "NetBSD 11.0".
	unameFamilyProbe{product: "netbsd", summary: "NetBSD", resolver: ResolverRef{Type: "endoflife", ID: "netbsd"}, unameName: "NetBSD"},
	// data-netbox-version on /login/, anonymous. Verified live (4.3.3).
	netboxProbe{},
	nextcloudProbe{},
	nexusProbe{},
	nginxProbe{},
	// Real ISO rootfs capture (the only Docker Hub image, nixos/nix, is
	// just the Nix package manager on a non-NixOS base with no
	// os-release at all — confirmed live, see DECISIONS.md D23):
	// ID=nixos, VERSION_ID="26.05".
	osReleaseFamilyProbe{product: "nixos", summary: "NixOS", resolver: ResolverRef{Type: "endoflife", ID: "nixos"}, match: osReleaseIDEquals("nixos")},
	oauth2ProxyProbe{},
	// /index.html (version, build, package type) plus /welcome/'s title for
	// the brand. Verified live: onlyoffice/documentserver:latest (9.4.0).
	onlyofficeFamilyProbe{product: "onlyoffice", summary: "ONLYOFFICE Docs (Document Server)", brand: "ONLYOFFICE", resolver: ResolverRef{Type: "github", ID: "ONLYOFFICE/DocumentServer"}},
	// Captured via vmactions/openbsd-vm (see uname.go): `uname -sr` -> "OpenBSD 7.9".
	unameFamilyProbe{product: "openbsd", summary: "OpenBSD", resolver: ResolverRef{Type: "endoflife", ID: "openbsd"}, unameName: "OpenBSD"},
	// Captured via vmactions/openeuler-vm (24.03-LTS-SP4, the action's
	// default release): ID="openEuler" (capital E, confirmed live — not
	// lowercase), VERSION_ID="24.03".
	osReleaseFamilyProbe{product: "openeuler", summary: "openEuler", match: osReleaseIDEquals("openEuler")},
	// The anonymous REST root /rest/, runtimeInfo.version. Verified live (5.2.2).
	openhabProbe{},
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
	osReleaseFamilyProbe{product: "oracle-linux", summary: "Oracle Linux", resolver: ResolverRef{Type: "endoflife", ID: "oracle-linux"}, match: osReleaseIDEquals("ol"), packages: packagesRPM},
	// Captured via vmactions/solaris-vm (see solaris.go): /etc/release's
	// "Oracle Solaris 11.4 X86" line.
	oracleSolarisProbe{},
	owncastProbe{},
	p4dProbe{},
	p4pProbe{},
	perforceSwarmProbe{},
	pfsenseProbe{},
	pgadminProbe{},
	// Official top-level photon:5.0 (Docker's Official Images program,
	// not vmware/photon's own stale repo which stops at 2.0): ID=photon,
	// VERSION_ID=5.0.
	osReleaseFamilyProbe{product: "photon", summary: "VMware Photon OS", resolver: ResolverRef{Type: "endoflife", ID: "photon"}, match: osReleaseIDEquals("photon")},
	phpmyadminProbe{},
	portainerProbe{},
	// window.POSTHOG_APP_CONTEXT.commit_sha on /login, anonymous. Verified
	// live on a production self-hosted instance.
	posthogProbe{},
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
	// Web UI API: form login, then /api/v2/app/version. Verified live
	// against linuxserver/qbittorrent 5.2.4.
	qbittorrentProbe{},
	// GET /api/overview on the management plugin, Basic auth. Verified live
	// against rabbitmq:4-management (4.3.6).
	rabbitmqProbe{},
	redisProbe{},
	// alrdockerhub/redos:7.3.1 (real RED OS content: HOME_URL/BUG_REPORT_URL
	// point at red-soft.ru): ID="redos", VERSION_ID="7.3.1".
	osReleaseFamilyProbe{product: "redos", summary: "RED OS", match: osReleaseIDEquals("redos"), packages: packagesRPM},
	// registry.redhat.io/ubi9 (Red Hat's own free Universal Base Image):
	// ID=rhel, VERSION_ID="9.8".
	osReleaseFamilyProbe{product: "rhel", summary: "Red Hat Enterprise Linux", resolver: ResolverRef{Type: "endoflife", ID: "rhel"}, match: osReleaseIDEquals("rhel"), packages: packagesRPM},
	// rockylinux:9: ID="rocky", VERSION_ID="9.3".
	osReleaseFamilyProbe{product: "rocky-linux", summary: "Rocky Linux", resolver: ResolverRef{Type: "endoflife", ID: "rocky-linux"}, match: osReleaseIDEquals("rocky"), packages: packagesRPM},
	routerosProbe{},
	// window.__initialData.version on the login page, anonymous. Verified
	// live against a production self-hosted Sentry 26.2.1.
	sentryProbe{},
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
	// Confirmed live against two real BMCs of different generations —
	// see supermicrobmc.go for why the check is Oem.Supermicro, not a
	// Manufacturer/Vendor field only one of the two actually has.
	supermicroBMCProbe{},
	// SYNO.API.Auth login, then GET SYNO.DSM.Info with the resulting
	// session id (and SynoToken, when CSRF protection is enabled).
	// Verified live against a real DSM 7.3.2 NAS.
	synologyDSMProbe{},
	teamcityProbe{},
	testrailProbe{},
	traefikProbe{},
	// GET /api/v2.0/system/info, authenticated with an API key as a plain
	// bearer token. Verified live against a real TrueNAS 25.10.7 host —
	// superseded an earlier SSH-based (/etc/version) version once this
	// became available (D2: one product, one probe, not both at once).
	truenasProbe{},
	// ubuntu:24.04: ID=ubuntu, VERSION_ID="24.04".
	// ubuntuProbe, not osReleaseFamilyProbe: VERSION_ID never carries the
	// point release ("22.04", not "22.04.5") — see ubuntu.go for why.
	ubuntuProbe{},
	// Logs in over socket.io (Engine.IO long-polling) and reads the version
	// from the post-login info event. Verified live on 1.23.17 and 2.5.5.
	uptimeKumaProbe{},
	vaultProbe{},
	bitwardenFamilyProbe{product: "vaultwarden", summary: "Vaultwarden", resolver: ResolverRef{Type: "github", ID: "dani-garcia/vaultwarden"}},
	vcenterProbe{},
	// GET /ping, anonymous. Verified live on a production WAPT 1.8.2 server.
	waptProbe{},
	// Anonymous: the "Powered by Weblate" footer on /about/. Verified live
	// against weblate/weblate:latest (2026.10).
	weblateProbe{},
	wordpressProbe{},
	youtrackProbe{},
	zabbixProbe{},
	// "srvr", the one four-letter word allowed by default. Verified live
	// against zookeeper:3.9 (3.9.6).
	zookeeperProbe{},
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
