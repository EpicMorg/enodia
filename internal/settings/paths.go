// SPDX-License-Identifier: AGPL-3.0-or-later

package settings

import (
	"fmt"
	"os"
	"path/filepath"
)

// candidateNames are the file names checked inside each directory-based
// search location (XDG, /etc), .yaml before .yml — both are equally common
// in the wild, and this package has no reason to prefer one, so ties are
// broken purely by which the search tries first. ./enodia.settings.{yaml,yml}
// and ./.enodia.settings.{yaml,yml} are checked by their own literal names
// instead — see Locate.
var candidateNames = []string{"settings.yaml", "settings.yml"}

// Locate finds the settings file to load, in this order:
//
//  1. explicit (the --settings flag). If set it must exist — same rule as
//     internal/config.Locate's --config, and for the same reason: naming a
//     file on purpose means a typo must surface as an error, not a silent
//     fall-through to built-in defaults.
//  2. $ENODIA_SETTINGS. Same rule.
//  3. ./enodia.settings.yaml
//  4. ./enodia.settings.yml
//  5. ./.enodia.settings.yaml
//  6. ./.enodia.settings.yml
//  7. $XDG_CONFIG_HOME/enodia/settings.yaml, defaulting to
//     ~/.config/enodia/settings.yaml per the XDG basedir spec when the
//     variable is unset.
//  8. $XDG_CONFIG_HOME/enodia/settings.yml (same fallback)
//  9. /etc/enodia/settings.yaml
//  10. /etc/enodia/settings.yml
//
// Unlike config.Locate, finding nothing at steps 3-10 is not an error: this
// file is entirely optional (D19). Locate returns ("", nil) in that case,
// and Resolve falls back to Default. Precedence is by location first (cwd,
// then XDG, then /etc), and only .yaml vs .yml within the same location —
// a cwd .yml still beats an XDG .yaml.
func Locate(explicit string) (string, error) {
	if explicit != "" {
		return mustExist(explicit)
	}
	if env := os.Getenv("ENODIA_SETTINGS"); env != "" {
		return mustExist(env)
	}

	candidates := []string{
		"enodia.settings.yaml", "enodia.settings.yml",
		".enodia.settings.yaml", ".enodia.settings.yml",
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
