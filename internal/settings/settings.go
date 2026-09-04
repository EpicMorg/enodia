// SPDX-License-Identifier: AGPL-3.0-or-later

// Package settings loads settings.yaml: per-operator display preferences,
// deliberately kept separate from enodia.yaml (see docs/DECISIONS.md D19).
// enodia.yaml is shared, often version-controlled, prod-facing data —
// targets and the credentials to reach them. Which table view is the
// default, or which Bootswatch theme a generated report opens in, is a
// personal choice with no bearing on what gets probed, so it lives here
// instead.
//
// A missing settings.yaml is not an error, unlike a missing enodia.yaml:
// this file is entirely optional, and Default returns exactly what every
// field behaves as when it is absent.
package settings

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// SchemaVersion is the highest settings shape this build understands. Same
// rule as internal/config.SchemaVersion, and for the same reason (D5): a
// file declaring a newer version is refused rather than parsed
// optimistically.
const SchemaVersion = 1

// DefaultTheme is used whenever html.theme is unset. It is also the value
// baked into every generated CDN-mode page as its own localStorage reset
// target (see internal/render's HTMLOptions): a bad or unknown stored theme
// resets to *this* setting, not to a hardcoded name unrelated to what the
// operator actually configured.
const DefaultTheme = "default"

// Settings is the parsed content of settings.yaml. Every field is optional;
// a zero Settings (what Default returns) means "use every built-in
// default".
type Settings struct {
	SchemaVersion int            `yaml:"schemaVersion"`
	Render        RenderSettings `yaml:"render,omitempty"`
	HTML          HTMLSettings   `yaml:"html,omitempty"`

	// path is where this was loaded from, kept only for error messages.
	path string
}

// RenderSettings controls the terminal table renderer.
type RenderSettings struct {
	// DefaultView is used by `check` (and `export --format html`, via
	// HTML.View when that is itself unset) whenever --view is not passed
	// on the command line. Empty means the built-in default (compact for
	// check; all four sections for html export).
	DefaultView string `yaml:"default_view,omitempty"`
}

// HTMLSettings controls `export --format html`. What the two Assets values
// mean, and what View/Theme do, is documented on internal/render's
// HTMLOptions — this struct is only the on-disk shape; it does not
// interpret its own fields; that is left to render, so this package does
// not need to enum-validate values render itself will reject clearly at
// export time.
type HTMLSettings struct {
	Assets string `yaml:"assets,omitempty"`
	View   string `yaml:"view,omitempty"`
	Theme  string `yaml:"theme,omitempty"`
}

// Default returns the all-built-in-defaults Settings: what's used when no
// settings.yaml exists anywhere Locate looks, which is normal, not an
// error.
func Default() *Settings {
	return &Settings{SchemaVersion: SchemaVersion}
}

// Resolve is the one call site normally needs: Locate the file (explicit
// path or the standard search), then Load it, or fall back to Default when
// nothing was found. explicit is the --settings flag value, "" meaning
// search.
func Resolve(explicit string) (*Settings, error) {
	path, err := Locate(explicit)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return Default(), nil
	}
	return Load(path)
}

// Load reads and validates the settings file at path.
func Load(path string) (*Settings, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading settings %s: %w", path, err)
	}

	var s Settings
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	s.path = path
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Validate checks only what this package itself owns: the schema version.
// html.assets/html.view/html.theme are validated by internal/render at the
// point they're actually used (HTMLOptions, viewRows) — duplicating that
// here would just be a second definition of what "valid" means, drifting
// out of sync with the first the moment either changes.
func (s *Settings) Validate() error {
	switch {
	case s.SchemaVersion == 0:
		return fmt.Errorf("%s: missing schemaVersion; add \"schemaVersion: %d\"", s.path, SchemaVersion)
	case s.SchemaVersion > SchemaVersion:
		return fmt.Errorf("%s: schemaVersion %d is newer than this build understands (max %d) — upgrade enodia",
			s.path, s.SchemaVersion, SchemaVersion)
	}
	return nil
}

// EffectiveTheme is HTML.Theme if set, else DefaultTheme.
func (s *Settings) EffectiveTheme() string {
	if s.HTML.Theme != "" {
		return s.HTML.Theme
	}
	return DefaultTheme
}
