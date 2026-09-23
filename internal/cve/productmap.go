// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

// productSoftNames maps an enodia product id to the exact <soft><name>
// strings BDU uses for it — confirmed live against the real export, not
// guessed from the product's own display name. BDU has no stable product
// identifier of its own (unlike endoflife.date's slugs or a GitHub
// owner/repo), just free-text vendor/product names, so this table is the
// only place that translation lives.
//
// Deliberately small and explicitly curated rather than an attempt at
// exhaustive coverage of every product enodia probes: Jira alone has over
// a dozen BDU name variants ("Jira", "Jira Server", "Jira Data Center",
// "Jira Software Data Center and Server", "Jira Service Management", ...)
// for what enodia treats as one product, and getting that full mapping
// right for every probe needs the same live-verification discipline this
// project already applies everywhere else — not something to rush through
// in one pass. Add entries here as each product gets checked against the
// real export, the same way registry.go grows one verified probe at a
// time.
var productSoftNames = map[string][]string{
	"confluence": {"Confluence Server", "Confluence Data Center"},
	"jira":       {"Jira", "Jira Server", "Jira Data Center"},
	"keycloak":   {"Keycloak"},
	"postgresql": {"PostgreSQL"},
}

// cpeName is one NVD CPE 2.3 (vendor, product) pair — the third and fourth
// colon-separated fields of a `criteria` string, e.g. "atlassian",
// "confluence_server". NVD has no free-text product name the way BDU
// does; every CVE's configurations reference a CPE instead, so this is
// the NVD equivalent of productSoftNames.
type cpeName struct{ vendor, product string }

// productCPENames maps an enodia product id to the CPE (vendor, product)
// pairs NVD uses for it — confirmed live against real CVE records'
// configurations, not the separate CPE dictionary API (cpes/2.0), which
// turned out live to disagree: e.g. the dictionary lists no
// "confluence_server"/"confluence_data_center" product at all (only a
// bare "confluence"), yet CVE-2023-22515's own configurations use exactly
// those two as match criteria. The dictionary catalogs known
// product+version combinations for browsing; it is not authoritative for
// what criteria strings a CVE's configurations actually use, so this
// table is built from real CVE data instead.
//
// Two more real quirks this table exists to route around instead of
// guessing past:
//   - Keycloak (the open-source project enodia's own probe targets) shows
//     up under two different vendors across its real CVE history —
//     "keycloak:keycloak" (older CVEs, e.g. CVE-2014-3709) and
//     "redhat:keycloak" (newer ones) — apparently a vendor re-registration
//     partway through, not a renamed or forked product. "redhat:
//     single_sign_on" (Red Hat's own commercial, differently-versioned
//     productization of Keycloak) is deliberately excluded: its versions
//     don't correspond to upstream Keycloak's numbering at all.
//   - Some Atlassian products distinguish Server from Data Center via the
//     CPE product slug itself (Confluence: confluence_server vs
//     confluence_data_center), others via the CPE "sw_edition" field on an
//     otherwise-identical product slug (Jira Service Desk: one
//     jira_service_desk product, "server" or "data_center" in
//     sw_edition) — confirmed live on real CVE-2019-14994/-15003 records.
//     This table only lists the slug-distinguished Jira variants that
//     correspond to what enodia's own "jira" probe targets (Jira
//     Software, not Service Desk/Service Management, a different product
//     with its own versioning); an sw_edition split would need matching
//     that field too, not attempted for the initial products below.
//
// Deliberately small and explicitly curated, same spirit and same reason
// as productSoftNames: add entries here as each product gets checked
// against real NVD data.
var productCPENames = map[string][]cpeName{
	"confluence": {{"atlassian", "confluence_server"}, {"atlassian", "confluence_data_center"}},
	"jira": {
		{"atlassian", "jira"}, {"atlassian", "jira_core"}, {"atlassian", "jira_server"},
		{"atlassian", "jira_software_data_center"}, {"atlassian", "jira_server_and_data_center"},
	},
	"keycloak":   {{"keycloak", "keycloak"}, {"redhat", "keycloak"}},
	"postgresql": {{"postgresql", "postgresql"}},
}
