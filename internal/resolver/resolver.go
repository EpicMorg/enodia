// SPDX-License-Identifier: AGPL-3.0-or-later

// Package resolver fetches the lifecycle calendar for a product — release
// cycles, and when each one goes from active support to security-only to
// end of life — from an external data source, with an on-disk cache.
//
// This package only gathers facts. Turning them into a verdict as of a given
// time is internal/evaluate's job (D7): a Cycle here is exactly what the
// upstream source published, not enodia's opinion about it.
package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/EpicMorg/enodia/internal/probe"
)

// maxBody caps how much of a source's response is read. A lifecycle
// calendar is at most a few hundred cycles; anything larger is the wrong
// endpoint or someone being hostile.
const maxBody = 1 << 20 // 1 MiB

// dateLayout is the YYYY-MM-DD format every date in these APIs uses.
const dateLayout = "2006-01-02"

// Date is a calendar date with no time-of-day or zone, as published by
// lifecycle APIs.
type Date struct{ time.Time }

func (d *Date) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("date must be a %q-formatted string: %w", dateLayout, err)
	}
	t, err := time.Parse(dateLayout, s)
	if err != nil {
		return fmt.Errorf("date %q is not in %q format: %w", s, dateLayout, err)
	}
	d.Time = t
	return nil
}

// MarshalJSON writes the date back out the same way it was read. Without
// this, json.Marshal would fall back to time.Time's own MarshalJSON
// (RFC 3339, with a time-of-day and zone), which UnmarshalJSON above cannot
// parse — breaking the on-disk cache's round trip the moment it wrote back
// anything with a release date.
func (d Date) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Format(dateLayout))
}

// Flag is a lifecycle-API value that is either a plain boolean or a date:
// endoflife.date reports fields like eol, support and lts as false ("does
// not apply / not yet"), true ("yes, but no specific date is published"), or
// a date marking exactly when the phase starts or started. A nil *Flag means
// the source did not report the field at all, which is a different thing
// from an explicit false — GitHub Releases, for one, never reports these at
// all.
type Flag struct {
	Bool   bool
	Date   time.Time
	IsDate bool
}

func (f *Flag) UnmarshalJSON(data []byte) error {
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		f.Bool = b
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("must be a bool or a %q-formatted date: %w", dateLayout, err)
	}
	t, err := time.Parse(dateLayout, s)
	if err != nil {
		return fmt.Errorf("%q is not a bool or a %q-formatted date: %w", s, dateLayout, err)
	}
	f.Date = t
	f.IsDate = true
	f.Bool = true
	return nil
}

// MarshalJSON writes back whichever form was read: a date string if IsDate,
// otherwise the plain bool. Same reasoning as Date.MarshalJSON — without
// this, the default struct marshaling (Bool/Date/IsDate as separate fields)
// would not round-trip through UnmarshalJSON at all.
func (f Flag) MarshalJSON() ([]byte, error) {
	if f.IsDate {
		return json.Marshal(f.Date.Format(dateLayout))
	}
	return json.Marshal(f.Bool)
}

// Cycle is one release branch's lifecycle facts, as published by a
// lifecycle data source.
type Cycle struct {
	Cycle             string `json:"cycle"`
	Latest            string `json:"latest,omitempty"`
	ReleaseDate       *Date  `json:"releaseDate,omitempty"`
	LatestReleaseDate *Date  `json:"latestReleaseDate,omitempty"`
	LTS               *Flag  `json:"lts,omitempty"`
	Support           *Flag  `json:"support,omitempty"`
	EOL               *Flag  `json:"eol,omitempty"`
	Discontinued      *Flag  `json:"discontinued,omitempty"`
}

// Source fetches lifecycle cycles for one resolver reference from one
// upstream data source.
type Source interface {
	Fetch(ctx context.Context, ref probe.ResolverRef) ([]Cycle, error)
}

// Resolver looks up lifecycle cycles for a product, preferring a fresh cache
// entry over a network round trip.
type Resolver struct {
	// Cache holds previously resolved cycles. Nil disables caching. Caching
	// matters here: fifty services commonly resolve to about eight distinct
	// products, so almost every run without a cache re-fetches data it
	// already has.
	Cache *Cache

	// Sources maps a ResolverRef.Type ("endoflife", "github") to the source
	// that understands it.
	Sources map[string]Source

	// Warn (optional) receives non-fatal notices — a corrupt or unwritable
	// cache entry, e.g. — the same way collect.Options.Warn does. Such
	// failures never fail Resolve as long as the network fetch itself
	// succeeds.
	Warn func(msg string)
}

// New builds a Resolver wired to the real endoflife.date and GitHub Releases
// sources. cache may be nil to disable caching.
func New(cache *Cache) *Resolver {
	return &Resolver{
		Cache: cache,
		Sources: map[string]Source{
			"endoflife": &endoflifeSource{Client: http.DefaultClient},
			"github":    &githubSource{Client: http.DefaultClient},
		},
	}
}

// Resolve returns the lifecycle cycles for ref.
//
// An empty ref.Type is not an error: it means the product has no known
// lifecycle calendar, which the roadmap treats as a normal, inventory-only
// state rather than a failure.
func (r *Resolver) Resolve(ctx context.Context, ref probe.ResolverRef) ([]Cycle, error) {
	if ref.Type == "" {
		return nil, nil
	}

	now := time.Now()
	if r.Cache != nil {
		cycles, hit, err := r.Cache.Load(ref, now)
		if err != nil {
			r.warn(fmt.Sprintf("lifecycle cache: %v", err))
		}
		if hit {
			return cycles, nil
		}
	}

	src, ok := r.Sources[ref.Type]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedType, ref.Type)
	}
	cycles, err := src.Fetch(ctx, ref)
	if err != nil {
		return nil, err
	}

	if r.Cache != nil {
		if err := r.Cache.Store(ref, cycles, now); err != nil {
			r.warn(fmt.Sprintf("lifecycle cache: %v", err))
		}
	}
	return cycles, nil
}

func (r *Resolver) warn(msg string) {
	if r.Warn != nil {
		r.Warn(msg)
	}
}
