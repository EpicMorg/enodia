// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// candidateName is the file name used inside the directory-based search
// locations (XDG, /etc). ./enodia.yaml and ./.enodia.yaml are checked by
// their own literal names instead — see Locate.
const candidateName = "enodia.yaml"

// Locate finds the config file to load, in this order:
//
//  1. explicit (the --config flag). If set it must exist; this is never a
//     fallback, because a typo here must surface as an error rather than
//     silently loading some other config with different credentials.
//  2. $ENODIA_CONFIG. Same rule and same reason: the user named this file on
//     purpose, so a miss is an error, not a cue to keep searching.
//  3. ./enodia.yaml
//  4. ./.enodia.yaml
//  5. $XDG_CONFIG_HOME/enodia/enodia.yaml, defaulting to
//     ~/.config/enodia/enodia.yaml per the XDG basedir spec when the
//     variable is unset.
//  6. /etc/enodia/enodia.yaml
//
// Only steps 3-6 are a search: a miss there just tries the next candidate.
// The first match wins outright — there is no merging of several found
// files.
func Locate(explicit string) (string, error) {
	if explicit != "" {
		return mustExist(explicit)
	}
	if env := os.Getenv("ENODIA_CONFIG"); env != "" {
		return mustExist(env)
	}

	candidates := []string{
		"enodia.yaml",
		".enodia.yaml",
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		candidates = append(candidates, filepath.Join(xdg, "enodia", candidateName))
	} else if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".config", "enodia", candidateName))
	}
	candidates = append(candidates, filepath.Join("/etc", "enodia", candidateName))

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
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
