// SPDX-License-Identifier: AGPL-3.0-or-later

// Package probe defines how Enodia asks a running service for its version.
//
// A probe owns its transport. The engine deliberately does not know whether a
// probe speaks HTTP, Redis or raw TCP — that knowledge stays inside the probe
// so that non-HTTP targets can be added without reshaping this interface.
package probe

import (
	"context"
	"net/http"
	"time"
)

// Probe reports the version of one product. One product, one probe.
type Probe interface {
	Meta() Meta
	Probe(ctx context.Context, t Target) (Observation, error)
}

// AuthKind is a credential shape a probe understands.
type AuthKind string

const (
	AuthNone        AuthKind = "none"
	AuthBearer      AuthKind = "bearer"       // Authorization: Bearer <value>
	AuthTokenHeader AuthKind = "token-header" // PRIVATE-TOKEN, X-Vault-Token, ...
	AuthBasic       AuthKind = "basic"
	AuthPassword    AuthKind = "password" // Redis AUTH, SQL connect, ...
)

// AuthSpec is what a probe declares it needs. It lets `config validate` reject
// a bad config offline, before a single packet is sent.
type AuthSpec struct {
	// Required means the probe cannot work at all without credentials.
	// Such a target is skipped, not failed, when credentials are absent.
	Required bool
	Kinds    []AuthKind
}

// Accepts reports whether the probe understands this credential shape.
func (a AuthSpec) Accepts(k AuthKind) bool {
	if k == AuthNone && !a.Required {
		return true
	}
	for _, x := range a.Kinds {
		if x == k {
			return true
		}
	}
	return false
}

// ResolverRef points at lifecycle data for a product. An empty Type means the
// product has no known lifecycle calendar — inventory only, which is a normal
// state and not an error.
type ResolverRef struct {
	Type string `json:"type,omitempty"` // "endoflife", "github", ...
	ID   string `json:"id,omitempty"`   // slug or owner/repo
}

// Meta describes a probe. It is static; it must not depend on user config.
type Meta struct {
	Product         string   // canonical id used in config: product: jira
	Aliases         []string // accepted alternative spellings
	Summary         string
	DefaultResolver ResolverRef
	Auth            AuthSpec
	DefaultScheme   string // "https" unless the product is plaintext by nature
}

// Credentials carries one target's secret. It must never be logged, embedded
// in an Observation, or written to the inventory.
type Credentials struct {
	Kind     AuthKind
	Value    string // token, for bearer and token-header
	Header   string // header name, for token-header
	Username string
	Password string
}

func (c Credentials) IsZero() bool {
	return c.Value == "" && c.Password == "" && c.Username == ""
}

// String prevents credentials from leaking through %v or %s.
func (c Credentials) String() string { return "Credentials{redacted}" }

// GoString prevents leaks through %#v.
func (c Credentials) GoString() string { return "Credentials{redacted}" }

// TLSSettings configures certificate verification for one target.
//
// The three levels, in descending order of correctness: a corporate CA bundle,
// a pinned certificate fingerprint, and finally giving up with Insecure.
type TLSSettings struct {
	CAFile     string   // PEM bundle to trust in addition to the system roots
	PinSHA256  []string // hex sha256 of the DER leaf certificate
	ServerName string   // SNI override, needed when connecting by IP
	MinVersion string   // "1.0".."1.3"; some legacy estates need 1.0
	Insecure   bool     // last resort; always warned about, always reported
}

// ParserSpec is the frozen escape hatch used by the generic probe. It is
// deliberately not extended: anything needing a conditional belongs in Go.
type ParserSpec struct {
	Type       string            `json:"type"`                 // json, xml, header, plaintext, regex
	Key        string            `json:"key,omitempty"`        // dotted path, XPath-ish tag, or header name
	Regex      string            `json:"regex,omitempty"`      // for type: regex
	CleanRegex string            `json:"cleanRegex,omitempty"` // first capture group wins
	Line       int               `json:"line,omitempty"`       // for type: plaintext
	Namespaces map[string]string `json:"namespaces,omitempty"`
}

// Target is one entry from the user's config, resolved and ready to probe.
type Target struct {
	ID      string // stable across renames; metrics and history key off this
	Name    string // display name
	Product string
	Address string // as written by the user; each probe parses it itself

	Creds   Credentials
	TLS     TLSSettings
	Timeout time.Duration

	// AllowInsecureTransport permits sending credentials over plain HTTP.
	// Off by default: without it, an http:// target carrying credentials is
	// an error rather than a warning.
	AllowInsecureTransport bool

	// Path and Method override the probe's defaults. Rarely needed.
	Path   string
	Method string

	// Headers are extra request headers from config.
	Headers map[string]string

	// Parser is consulted by the generic probe only.
	Parser *ParserSpec

	// Options carries probe-specific settings from config.
	Options map[string]string

	// HTTP is a shared client built from TLS settings and timeouts.
	// Non-HTTP probes ignore it. Sharing it preserves connection pooling.
	HTTP *http.Client
}

// Observation is what a probe saw. It contains facts only — no verdicts, and
// under no circumstances any credential. It is serialised into the inventory,
// which is expected to leave the network it was collected on.
type Observation struct {
	Kind    string `json:"kind"` // always "observation"
	ID      string `json:"id"`
	Name    string `json:"name"`
	Product string `json:"product,omitempty"`

	Version    string `json:"version,omitempty"`    // exactly as the service reported it
	Normalized string `json:"normalized,omitempty"` // cleaned for comparison
	Edition    string `json:"edition,omitempty"`    // ee/ce, enterprise/community

	Endpoint string            `json:"endpoint,omitempty"` // what was actually queried
	Extra    map[string]string `json:"extra,omitempty"`    // buildNumber, typeId, ...

	// TLSVerified is nil for non-TLS transports. False means the certificate
	// was not verified — surfaced in reports as a fleet-wide TLS audit.
	TLSVerified *bool `json:"tlsVerified,omitempty"`

	Error     string `json:"error,omitempty"`
	ErrorKind string `json:"errorKind,omitempty"` // unreachable, auth, not_supported, unparseable, skipped

	CollectedAt time.Time `json:"collectedAt"`
	DurationMS  int64     `json:"durationMs,omitempty"`
}

// OK reports whether a version was obtained.
func (o Observation) OK() bool { return o.Error == "" && o.Version != "" }
