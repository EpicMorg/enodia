// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"fmt"
	"os"
	"regexp"
)

// interpVar matches ${VAR} and ${VAR:-default}. VAR follows shell identifier
// rules; default may be empty and may not itself contain "}".
var interpVar = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}`)

// envLookup is the lookup Load uses in production; tests inject their own so
// interpolation stays independent of the process environment.
func envLookup(name string) (string, bool) { return os.LookupEnv(name) }

// Interpolate expands ${VAR} and ${VAR:-default} in raw using lookup.
//
// It runs on the raw file bytes before YAML parsing, so it applies uniformly
// to every scalar in the file without needing to walk the parsed tree.
//
// ${VAR} with no default is an error when VAR is unset — the :-default form
// exists precisely for the case where an unset variable is fine. A variable
// that is set but empty is treated as unset for the purpose of choosing a
// default, matching shell ${VAR:-default} semantics; with no default, a
// set-but-empty value passes through as an empty string.
func Interpolate(raw []byte, lookup func(string) (string, bool)) ([]byte, error) {
	var firstErr error
	out := interpVar.ReplaceAllFunc(raw, func(m []byte) []byte {
		if firstErr != nil {
			return m
		}
		groups := interpVar.FindSubmatch(m)
		name := string(groups[1])
		hasDefault := len(groups[2]) > 0
		def := string(groups[3])

		val, ok := lookup(name)
		switch {
		case ok && val != "":
			return []byte(val)
		case hasDefault:
			return []byte(def)
		case ok:
			return []byte(val) // set but empty, no default
		default:
			firstErr = fmt.Errorf("${%s} is not set and has no default", name)
			return m
		}
	})
	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}
