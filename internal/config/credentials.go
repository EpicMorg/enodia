// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"

	"github.com/EpicMorg/enodia/internal/probe"
)

// LoadCredentials builds the credential store for c: entries declared in
// credentials_file take precedence over entries of the same name declared
// inline in enodia.yaml. The separate file exists so real secrets can live
// outside a checked-in config that merely references them by name; letting
// the file win over an inline placeholder of the same name is what makes
// that override actually work. warn (may be nil) receives a notice when
// credentials_file is more permissive than 0600.
func (c *Config) LoadCredentials(warn func(string)) (map[string]CredentialSpec, error) {
	store := make(map[string]CredentialSpec, len(c.Credentials))
	for name, spec := range c.Credentials {
		store[name] = spec
	}

	if c.CredentialsFile == "" {
		return store, nil
	}

	credPath := c.CredentialsFile
	if !filepath.IsAbs(credPath) && c.path != "" {
		credPath = filepath.Join(filepath.Dir(c.path), credPath)
	}

	if warn != nil {
		if msg := permissionWarning(credPath); msg != "" {
			warn(msg)
		}
	}

	raw, err := os.ReadFile(credPath)
	if err != nil {
		return nil, fmt.Errorf("reading credentials_file %s: %w", credPath, err)
	}
	interpolated, err := Interpolate(raw, envLookup)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", credPath, err)
	}

	var f struct {
		Credentials map[string]CredentialSpec `yaml:"credentials"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(interpolated))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", credPath, err)
	}

	for name, spec := range f.Credentials {
		store[name] = spec // credentials_file wins over inline of the same name
	}
	return store, nil
}

// permissionWarning reports non-empty when path is readable or writable by
// anyone other than its owner. Credentials files have a habit of being
// copied around with the wrong mode and then living that way for years.
func permissionWarning(path string) string {
	if runtime.GOOS == "windows" {
		return "" // POSIX permission bits are not meaningful there
	}
	info, err := os.Stat(path)
	if err != nil {
		return "" // surfaces as a read error momentarily
	}
	if info.Mode().Perm()&^0o600 != 0 {
		return fmt.Sprintf("%s is mode %04o; group or other can access it — chmod 0600", path, info.Mode().Perm())
	}
	return ""
}

// resolveCredential looks up name in store and converts it to the shape
// probes consume. An empty name is not an error: it means the target is
// probed without credentials.
func resolveCredential(name string, store map[string]CredentialSpec) (probe.Credentials, error) {
	if name == "" {
		return probe.Credentials{}, nil
	}
	spec, ok := store[name]
	if !ok {
		return probe.Credentials{}, fmt.Errorf("%w: %q", ErrCredentialNotFound, name)
	}
	kind, err := parseAuthKind(spec.Kind)
	if err != nil {
		return probe.Credentials{}, fmt.Errorf("credential %q: %w", name, err)
	}
	return probe.Credentials{
		Kind:     kind,
		Value:    spec.Value,
		Header:   spec.Header,
		Username: spec.Username,
		Password: spec.Password,
	}, nil
}

func parseAuthKind(s string) (probe.AuthKind, error) {
	switch probe.AuthKind(s) {
	case probe.AuthNone, probe.AuthBearer, probe.AuthTokenHeader, probe.AuthBasic, probe.AuthPassword:
		return probe.AuthKind(s), nil
	case "":
		return probe.AuthNone, nil
	default:
		return "", fmt.Errorf("unknown credential kind %q", s)
	}
}
