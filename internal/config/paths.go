// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// candidateNames are the file names checked inside each directory-based
// search location (XDG, /etc), .yaml before .yml — both are equally common
// in the wild, and this package has no reason to prefer one, so ties are
// broken purely by which the search tries first. ./enodia.{yaml,yml} and
// ./.enodia.{yaml,yml} are checked by their own literal names instead —
// see Locate.
var candidateNames = []string{"enodia.yaml", "enodia.yml"}

// Locate finds the config file to load, in this order:
//
//  1. explicit (the --config flag). If set it must exist; this is never a
//     fallback, because a typo here must surface as an error rather than
//     silently loading some other config with different credentials.
//  2. $ENODIA_CONFIG. Same rule and same reason: the user named this file on
//     purpose, so a miss is an error, not a cue to keep searching.
//  3. ./enodia.yaml
//  4. ./enodia.yml
//  5. ./.enodia.yaml
//  6. ./.enodia.yml
//  7. $XDG_CONFIG_HOME/enodia/enodia.yaml, defaulting to
//     ~/.config/enodia/enodia.yaml per the XDG basedir spec when the
//     variable is unset.
//  8. $XDG_CONFIG_HOME/enodia/enodia.yml (same fallback)
//  9. /etc/enodia/enodia.yaml
//  10. /etc/enodia/enodia.yml
//
// Only steps 3-10 are a search: a miss there just tries the next candidate.
// The first match wins outright — there is no merging of several found
// files. Precedence is by location first (cwd, then XDG, then /etc), and
// only .yaml vs .yml within the same location — a cwd .yml still beats an
// XDG .yaml, exactly as a cwd .yaml already beat an XDG one.
func Locate(explicit string) (string, error) {
	if explicit != "" {
		return mustExist(explicit)
	}
	if env := os.Getenv("ENODIA_CONFIG"); env != "" {
		return mustExist(env)
	}

	candidates := []string{
		"enodia.yaml", "enodia.yml",
		".enodia.yaml", ".enodia.yml",
	}

	var dirs []string
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		dirs = append(dirs, filepath.Join(xdg, "enodia"))
	} else if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".config", "enodia"))
	}
	dirs = append(dirs, filepath.Join("/etc", "enodia"))

	for _, dir := range dirs {
		for _, name := range candidateNames {
			candidates = append(candidates, filepath.Join(dir, name))
		}
	}

	for _, c := range candidates {
		if fileExists(c) {
			return c, nil
		}
	}
	return "", fmt.Errorf("%w: looked in %v", ErrNotFound, candidates)
}

func mustExist(path string) (string, error) {
	if !fileExists(path) {
		return "", fmt.Errorf("config file %s does not exist", path)
	}
	return path, nil
}

func fileExists(path string) bool {
	//nolint:gosec // path is --config/$ENODIA_CONFIG or a fixed search candidate the operator controls, not untrusted input
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
