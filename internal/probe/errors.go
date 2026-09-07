// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import "errors"

// Sentinel errors. Probes wrap these with %w so the runner can decide whether
// to retry and the report can tell the user whose problem it is.
//
//   - ErrUnreachable  their network, possibly transient  -> retry
//   - ErrAuth         their token                        -> do not retry
//   - ErrNotSupported wrong product behind this address  -> do not retry
//   - ErrUnparseable  OUR bug: the vendor changed shape  -> do not retry, file an issue
var (
	ErrUnreachable  = errors.New("unreachable")
	ErrAuth         = errors.New("authentication failed")
	ErrNotSupported = errors.New("not supported by this probe")
	ErrUnparseable  = errors.New("response could not be parsed")
	ErrSkipped      = errors.New("skipped")
	ErrInsecure     = errors.New("refusing to send credentials over plaintext transport")
)

// Kind maps an error onto the stable string recorded in the inventory.
func Kind(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrAuth):
		return "auth"
	case errors.Is(err, ErrNotSupported):
		return "not_supported"
	case errors.Is(err, ErrUnparseable):
		return "unparseable"
	case errors.Is(err, ErrSkipped):
		return "skipped"
	case errors.Is(err, ErrInsecure):
		return "insecure"
	case errors.Is(err, ErrUnreachable):
		return "unreachable"
	default:
		return "error"
	}
}

// Retryable reports whether repeating the request could plausibly help.
// A bad token does not fix itself, and hammering a production Jira to find
// that out again is rude.
func Retryable(err error) bool { return errors.Is(err, ErrUnreachable) }
