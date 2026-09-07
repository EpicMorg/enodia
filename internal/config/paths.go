// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// candidateNames are the file names checked inside each directory-based
// search location (XDG, /etc): the enodia.-prefixed form first, then the
// bare "config" form (a natural fit there — the directory itself is
// already namespaced as .../enodia/, so "config.yaml" inside it isn't
// ambiguous the way a bare config.yaml in an arbitrary cwd could be), and
// .yaml before .yml within each — both are equally common in the wild, so
// ties are broken purely by which the search tries first. The four cwd
// forms (./enodia.{yaml,yml}, ./config.{yaml,yml}, and their two dotfile
// counterparts) are checked by their own literal names instead — see
// Locate.
var candidateNames = []string{"enodia.yaml", "enodia.yml", "config.yaml", "config.yml"}

// Locate finds the config file to load, in this order:
//
//  1. explicit (the --config flag). If set it must exist; this is never a
//     fallback, because a typo here must surface as an error rather than
//     silently loading some other config with different credentials.
//  2. $ENODIA_CONFIG. Same rule and same reason: the user named this file on
//     purpose, so a miss is an error, not a cue to keep searching.
//  3. ./enodia.yaml
//  4. ./enodia.yml
//  5. ./config.yaml — the bare name a plain "config.yaml next to the
//     binary" expectation reaches for, added after settings.yaml got the
//     same treatment for the same reason: the enodia.-prefixed form above
//     still wins if both exist.
//  6. ./config.yml
//  7. ./.enodia.yaml
//  8. ./.enodia.yml
//  9. ./.config.yaml
//  10. ./.config.yml
//  11. $XDG_CONFIG_HOME/enodia/enodia.yaml, defaulting to
//     ~/.config/enodia/enodia.yaml per the XDG basedir spec when the
//     variable is unset.
//  12. $XDG_CONFIG_HOME/enodia/enodia.yml (same fallback)
//  13. $XDG_CONFIG_HOME/enodia/config.yaml (same fallback)
//  14. $XDG_CONFIG_HOME/enodia/config.yml (same fallback)
//  15. /etc/enodia/enodia.yaml
//  16. /etc/enodia/enodia.yml
//  17. /etc/enodia/config.yaml
//  18. /etc/enodia/config.yml
//
// Only steps 3-18 are a search: a miss there just tries the next candidate.
// The first match wins outright — there is no merging of several found
// files. Precedence is by location first (cwd, then XDG, then /etc), and
// only naming (enodia. vs bare vs dotfile, and .yaml vs .yml) within the
// same location — a cwd .yml still beats an XDG .yaml, exactly as a cwd
// .yaml already beat an XDG one.
func Locate(explicit string) (string, error) {
	if explicit != "" {
		return mustExist(explicit)
	}
	if env := os.Getenv("ENODIA_CONFIG"); env != "" {
		return mustExist(env)
	}

	candidates := []string{
		"enodia.yaml", "enodia.yml",
		"config.yaml", "config.yml",
		".enodia.yaml", ".enodia.yml",
		".config.yaml", ".config.yml",
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
