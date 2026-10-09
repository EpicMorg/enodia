// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import "errors"

// ErrNotFound means no config file could be located in any of the
// well-known search locations.
var ErrNotFound = errors.New("no config file found")

// ErrCredentialNotFound means a target names a credential that resolves to
// nothing in either the inline store or credentials_file.
var ErrCredentialNotFound = errors.New("credential not found")

// ErrCredentialKind means a target's credential is of a kind its probe
// doesn't use — e.g. kind: password on an HTTP product, which only reads
// kind: basic. Without this check such a credential was silently dropped
// and the request went out with no Authorization header at all.
var ErrCredentialKind = errors.New("credential kind not accepted by this product")
