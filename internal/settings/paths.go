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
//  5. ./settings.yaml — the bare name a plain "settings.yaml next to the
//     binary" expectation reaches for; the enodia.-prefixed form above
//     still wins if both exist, since config.yaml-style prod data files
//     already train that prefix, but this file is personal and optional
//     (D19), so it doesn't need the same collision-avoidance the
//     credentials-bearing enodia.yaml does.
//  6. ./settings.yml
//  7. ./.enodia.settings.yaml
//  8. ./.enodia.settings.yml
//  9. ./.settings.yaml — the dotfile counterpart of the bare form above,
//     same as enodia.yaml/.enodia.yaml already pair up.
//  10. ./.settings.yml
//  11. <directory containing the running executable>/settings.yaml — the
//     actual "next to the binary" case, distinct from cwd: a portable
//     install (unzip anywhere, no package manager) is run from whatever
//     directory the operator happens to be standing in, which on Windows
//     in particular is essentially never the install directory itself
//     (install.ps1 defaults to %LOCALAPPDATA%\enodia, added to PATH — the
//     whole point of PATH is that cwd stops mattering). Deliberately
//     limited to settings.yaml: this file is optional display preferences
//     (D19), so a wrong or hijacked one in a shared install directory is a
//     cosmetic problem at worst. enodia.yaml carries credentials and stays
//     off this list — config.Locate does not gain an equivalent step.
//  12. <same>/settings.yml
//  13. $XDG_CONFIG_HOME/enodia/settings.yaml, defaulting to
//     ~/.config/enodia/settings.yaml per the XDG basedir spec when the
//     variable is unset.
//  14. $XDG_CONFIG_HOME/enodia/settings.yml (same fallback)
//  15. /etc/enodia/settings.yaml
//  16. /etc/enodia/settings.yml
//
// Unlike config.Locate, finding nothing at steps 3-16 is not an error: this
// file is entirely optional (D19). Locate returns ("", nil) in that case,
// and Resolve falls back to Default. Precedence is by location first (cwd,
// then the executable's directory, then XDG, then /etc), and only naming
// (enodia.-prefixed vs bare vs dotfile, and .yaml vs .yml) within the same
// location — a cwd .yml still beats an XDG .yaml.
func Locate(explicit string) (string, error) {
	if explicit != "" {
		return mustExist(explicit)
	}
	if env := os.Getenv("ENODIA_SETTINGS"); env != "" {
		return mustExist(env)
	}

	candidates := []string{
		"enodia.settings.yaml", "enodia.settings.yml",
		"settings.yaml", "settings.yml",
		".enodia.settings.yaml", ".enodia.settings.yml",
		".settings.yaml", ".settings.yml",
	}

	var dirs []string
	if exeDir := executableDir(); exeDir != "" {
		dirs = append(dirs, exeDir)
	}
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

// executableDir resolves the directory containing the running binary, or
// "" if that can't be determined (os.Executable is best-effort on some
// platforms per its own docs). Symlinks are resolved so a PATH shim (e.g. a
// version manager) doesn't make settings.yaml appear to live somewhere the
// real binary never runs from.
func executableDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Dir(exe)
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
