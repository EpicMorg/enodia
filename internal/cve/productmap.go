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
