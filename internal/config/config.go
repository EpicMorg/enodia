// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config loads enodia.yaml: schema validation, ${VAR} interpolation,
// the credential store, and config-file discovery.
package config

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/EpicMorg/enodia/internal/probe"
)

// SchemaVersion is the highest config shape this build understands. A config
// declaring a newer version is refused rather than parsed optimistically —
// the same rule D5 applies to the inventory format, and for the same reason.
const SchemaVersion = 1

// defaultTimeout applies when neither a target nor Defaults sets one.
const defaultTimeout = 10 * time.Second

// Config is the parsed content of enodia.yaml, before credentials are
// resolved.
type Config struct {
	SchemaVersion   int                       `yaml:"schemaVersion"`
	CredentialsFile string                    `yaml:"credentials_file,omitempty"`
	Defaults        Defaults                  `yaml:"defaults,omitempty"`
	Credentials     map[string]CredentialSpec `yaml:"credentials,omitempty"`
	Targets         []TargetSpec              `yaml:"targets,omitempty"`

	// path is where this config was loaded from. Kept so error messages can
	// name the file and so credentials_file resolves relative to it rather
	// than to the process's working directory.
	path string
}

// Defaults apply to every target that does not override them.
type Defaults struct {
	Timeout     Duration `yaml:"timeout,omitempty"`
	Concurrency int      `yaml:"concurrency,omitempty"`
	Retries     int      `yaml:"retries,omitempty"`
	Backoff     Duration `yaml:"backoff,omitempty"`
}

// TLSSpec is the on-disk shape of probe.TLSSettings.
type TLSSpec struct {
	CAFile     string   `yaml:"ca_file,omitempty"`
	PinSHA256  []string `yaml:"pin_sha256,omitempty"`
	ServerName string   `yaml:"server_name,omitempty"`
	MinVersion string   `yaml:"min_version,omitempty"`
	Insecure   bool     `yaml:"insecure,omitempty"`
}

// CredentialSpec is one named credential, sourced from either enodia.yaml's
// own credentials: map or the separate credentials_file.
type CredentialSpec struct {
	Kind     string `yaml:"kind"`
	Value    string `yaml:"value,omitempty"`
	Header   string `yaml:"header,omitempty"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
}

// TargetSpec is one service entry from config.
type TargetSpec struct {
	ID      string `yaml:"id"`
	Name    string `yaml:"name,omitempty"`
	Product string `yaml:"product"`
	Address string `yaml:"address"`

	// Credentials names an entry in the credential store. Empty means the
	// target is probed without credentials.
	Credentials string `yaml:"credentials,omitempty"`

	TLS                    TLSSpec           `yaml:"tls,omitempty"`
	AllowInsecureTransport bool              `yaml:"allow_insecure_transport,omitempty"`
	Timeout                Duration          `yaml:"timeout,omitempty"`
	Path                   string            `yaml:"path,omitempty"`
	Method                 string            `yaml:"method,omitempty"`
	Headers                map[string]string `yaml:"headers,omitempty"`

	// Parser is probe.ParserSpec directly: the generic probe's vocabulary is
	// frozen (D3), and this package must not fork a second definition of it.
	Parser *probe.ParserSpec `yaml:"parser,omitempty"`

	Options map[string]string `yaml:"options,omitempty"`
}

// Load reads, interpolates and validates the config file at path. It does
// not resolve credentials or build probe.Target values — call LoadCredentials
// and Build for that, once a warn sink is available.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	c, err := parse(raw, path)
	if err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func parse(raw []byte, path string) (*Config, error) {
	interpolated, err := Interpolate(raw, envLookup)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(interpolated))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	c.path = path
	return &c, nil
}

// Validate checks the schema version and every target for the errors that
// would otherwise only surface as a confusing failure deep in collection.
func (c *Config) Validate() error {
	switch {
	case c.SchemaVersion == 0:
		return fmt.Errorf("%s: missing schemaVersion; add \"schemaVersion: %d\"", c.path, SchemaVersion)
	case c.SchemaVersion > SchemaVersion:
		return fmt.Errorf("%s: schemaVersion %d is newer than this build understands (max %d) — upgrade enodia",
			c.path, c.SchemaVersion, SchemaVersion)
	}

	seen := make(map[string]bool, len(c.Targets))
	for i, t := range c.Targets {
		if t.ID == "" {
			return fmt.Errorf("%s: target %d: missing id", c.path, i)
		}
		if seen[t.ID] {
			return fmt.Errorf("%s: duplicate target id %q", c.path, t.ID)
		}
		seen[t.ID] = true
		if t.Product == "" {
			return fmt.Errorf("%s: target %q: missing product", c.path, t.ID)
		}
		if t.Address == "" {
			return fmt.Errorf("%s: target %q: missing address", c.path, t.ID)
		}
	}
	return nil
}

// Build resolves every target against the credential store and TLS settings,
// producing what internal/collect needs to run. warn receives non-fatal
// notices (a permissive credentials_file, e.g.) the same way
// collect.Options.Warn does; it may be nil.
func (c *Config) Build(warn func(string)) ([]probe.Target, error) {
	store, err := c.LoadCredentials(warn)
	if err != nil {
		return nil, err
	}

	timeout := time.Duration(c.Defaults.Timeout)
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	out := make([]probe.Target, 0, len(c.Targets))
	for _, ts := range c.Targets {
		creds, err := resolveCredential(ts.Credentials, store)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", ts.ID, err)
		}

		tt := timeout
		if ts.Timeout > 0 {
			tt = time.Duration(ts.Timeout)
		}

		tls := probe.TLSSettings{
			CAFile:     ts.TLS.CAFile,
			PinSHA256:  ts.TLS.PinSHA256,
			ServerName: ts.TLS.ServerName,
			MinVersion: ts.TLS.MinVersion,
			Insecure:   ts.TLS.Insecure,
		}
		client, err := probe.NewHTTPClient(tls, tt)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", ts.ID, err)
		}

		name := ts.Name
		if name == "" {
			name = ts.ID
		}

		out = append(out, probe.Target{
			ID:                     ts.ID,
			Name:                   name,
			Product:                ts.Product,
			Address:                ts.Address,
			Creds:                  creds,
			TLS:                    tls,
			Timeout:                tt,
			AllowInsecureTransport: ts.AllowInsecureTransport,
			Path:                   ts.Path,
			Method:                 ts.Method,
			Headers:                ts.Headers,
			Parser:                 ts.Parser,
			Options:                ts.Options,
			HTTP:                   client,
		})
	}
	return out, nil
}
