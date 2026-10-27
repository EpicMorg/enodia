// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// interpVar matches ${VAR} and ${VAR:-default}. VAR follows shell identifier
// rules; default may be empty and may not itself contain "}".
var interpVar = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}`)

// envLookup is the lookup Load uses in production; tests inject their own so
// interpolation stays independent of the process environment.
func envLookup(name string) (string, bool) { return os.LookupEnv(name) }

// interpolateNode expands ${VAR} and ${VAR:-default} in every scalar of the
// parsed YAML tree, in place.
//
// Interpolation runs on the parsed tree, not on the file's raw bytes, so a
// variable's value is taken verbatim however it is written: a password with a
// backslash, a '#', a ': ' or a leading '*'/'&'/'[' can no longer break the
// scalar it lands in, because the file has already been tokenised without it.
// A scalar that gains a value is retagged !!str (and re-emitted quoted as
// needed when the tree is marshalled back), so the substituted text is never
// re-resolved as a number, bool or null. Scalars with no ${...} are left
// exactly as they were, so literals in the file keep their own types.
//
// ${VAR} with no default is an error when VAR is unset — the :-default form
// exists precisely for the case where an unset variable is fine. A variable
// that is set but empty is treated as unset for the purpose of choosing a
// default, matching shell ${VAR:-default} semantics; with no default, a
// set-but-empty value passes through as an empty string.
func interpolateNode(n *yaml.Node, lookup func(string) (string, bool)) error {
	if n.Kind == yaml.ScalarNode {
		if !interpVar.MatchString(n.Value) {
			return nil
		}
		v, err := expand(n.Value, lookup)
		if err != nil {
			return err
		}
		n.Value = v
		n.Tag = "!!str"
		n.Style = 0 // let the encoder choose quoting that round-trips v
		return nil
	}
	for _, c := range n.Content {
		if err := interpolateNode(c, lookup); err != nil {
			return err
		}
	}
	return nil
}

// expand substitutes every ${VAR}/${VAR:-default} in a single scalar value.
func expand(value string, lookup func(string) (string, bool)) (string, error) {
	var firstErr error
	out := interpVar.ReplaceAllStringFunc(value, func(m string) string {
		if firstErr != nil {
			return m
		}
		groups := interpVar.FindStringSubmatch(m)
		name := groups[1]
		hasDefault := len(groups[2]) > 0
		def := groups[3]

		val, ok := lookup(name)
		switch {
		case ok && val != "":
			return val
		case hasDefault:
			return def
		case ok:
			return val // set but empty, no default
		default:
			firstErr = fmt.Errorf("${%s} is not set and has no default", name)
			return m
		}
	})
	if firstErr != nil {
		return "", firstErr
	}
	return out, nil
}
