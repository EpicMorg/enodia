// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import "errors"

// ErrNotFound means no config file could be located in any of the
// well-known search locations.
var ErrNotFound = errors.New("no config file found")

// ErrCredentialNotFound means a target names a credential that resolves to
// nothing in either the inline store or credentials_file.
var ErrCredentialNotFound = errors.New("credential not found")
