// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"fmt"
	"sort"
)

// builtin is the complete list of compiled-in probes.
//
// Registration is explicit rather than via init(): this slice is meant to read
// as a table of contents, and a pull request adding a product should be
// visible here. Ordering is alphabetical by product.
var builtin = []Probe{
	&atlassianProbe{product: "bamboo", typeID: "bamboo", resolver: "", summary: "Atlassian Bamboo (Data Center)"},
	&atlassianProbe{product: "bitbucket", typeID: "stash", resolver: "bitbucket", summary: "Atlassian Bitbucket (Data Center)"},
	&atlassianProbe{product: "confluence", typeID: "confluence", resolver: "confluence", summary: "Atlassian Confluence (Data Center)"},
	genericProbe{},
	&atlassianProbe{product: "jira", typeID: "jira", resolver: "jira-software", summary: "Atlassian Jira (Data Center)"},
	mysqlProbe{},
	postgresProbe{},
	redisProbe{},
	sshProbe{},
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
