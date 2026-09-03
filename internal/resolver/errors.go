// SPDX-License-Identifier: AGPL-3.0-or-later

package resolver

import "errors"

// Sentinel errors from a lifecycle data source or the cache.
//
//   - ErrUnknownProduct  the source has never heard of this product/repo
//   - ErrUnreachable     network or HTTP-level failure talking to the source
//   - ErrUnparseable     the source replied but its shape changed under us
//   - ErrUnsupportedType no Source is registered for a ResolverRef.Type
var (
	ErrUnknownProduct  = errors.New("lifecycle data source has no data for this product")
	ErrUnreachable     = errors.New("lifecycle data source unreachable")
	ErrUnparseable     = errors.New("lifecycle data source response could not be parsed")
	ErrUnsupportedType = errors.New("no lifecycle source registered for this resolver type")
)
