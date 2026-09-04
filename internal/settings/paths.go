// SPDX-License-Identifier: AGPL-3.0-or-later

package settings

import (
	"fmt"
	"os"
	"path/filepath"
)

// candidateName is the file name used inside the directory-based search
// locations (XDG, /etc). ./enodia.settings.yaml and ./.enodia.settings.yaml
// are checked by their own literal names instead — see Locate.
const candidateName = "settings.yaml"

// Locate finds the settings file to load, in this order:
//
//  1. explicit (the --settings flag). If set it must exist — same rule as
//     internal/config.Locate's --config, and for the same reason: naming a
//     file on purpose means a typo must surface as an error, not a silent
//     fall-through to built-in defaults.
//  2. $ENODIA_SETTINGS. Same rule.
//  3. ./enodia.settings.yaml
//  4. ./.enodia.settings.yaml
//  5. $XDG_CONFIG_HOME/enodia/settings.yaml, defaulting to
//     ~/.config/enodia/settings.yaml per the XDG basedir spec when the
//     variable is unset.
//  6. /etc/enodia/settings.yaml
//
// Unlike config.Locate, finding nothing at steps 3-6 is not an error: this
// file is entirely optional (D19). Locate returns ("", nil) in that case,
// and Resolve falls back to Default.
func Locate(explicit string) (string, error) {
	if explicit != "" {
		return mustExist(explicit)
	}
	if env := os.Getenv("ENODIA_SETTINGS"); env != "" {
		return mustExist(env)
	}

	candidates := []string{
		"enodia.settings.yaml",
		".enodia.settings.yaml",
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
	return "", nil
}

func mustExist(path string) (string, error) {
	if !fileExists(path) {
		return "", fmt.Errorf("settings file %s does not exist", path)
	}
	return path, nil
}

func fileExists(path string) bool {
	//nolint:gosec // path is --settings/$ENODIA_SETTINGS or a fixed search candidate the operator controls, not untrusted input
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
