// SPDX-License-Identifier: AGPL-3.0-or-later

// Package collect runs probes across a fleet, concurrently and politely.
package collect

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/EpicMorg/enodia/internal/probe"
	"github.com/EpicMorg/enodia/internal/version"
)

// Options tunes a collection run.
type Options struct {
	Concurrency int
	Retries     int           // extra attempts, transient failures only
	Backoff     time.Duration // base delay, doubled per attempt with jitter
	Warn        func(target probe.Target, msg string)
}

func (o *Options) defaults() {
	if o.Concurrency <= 0 {
		o.Concurrency = 16
	}
	if o.Backoff <= 0 {
		o.Backoff = 500 * time.Millisecond
	}
	if o.Warn == nil {
		o.Warn = func(probe.Target, string) {}
	}
}

// Run probes every target and returns observations in input order.
//
// Retries live here rather than in probes so that every probe retries the same
// way, and so that a failure which cannot improve — a rejected token, a broken
// parser — is not repeated against production.
func Run(ctx context.Context, targets []probe.Target, opts Options) []probe.Observation {
	opts.defaults()

	out := make([]probe.Observation, len(targets))
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup

	for i, t := range targets {
		wg.Add(1)
		go func(i int, t probe.Target) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				out[i] = failed(t, fmt.Errorf("%w: cancelled", probe.ErrUnreachable))
				return
			}
			defer func() { <-sem }()
			out[i] = one(ctx, t, opts)
		}(i, t)
	}
	wg.Wait()
	return out
}

func one(ctx context.Context, t probe.Target, opts Options) probe.Observation {
	p, err := probe.Get(t.Product)
	if err != nil {
		return failed(t, fmt.Errorf("%w: %w", probe.ErrNotSupported, err))
	}
	meta := p.Meta()

	// A target whose probe cannot work without credentials, and has none, is
	// skipped rather than failed: shared configs legitimately cover services
	// the current operator has no token for.
	if meta.Auth.Required && t.Creds.IsZero() {
		obs := failed(t, fmt.Errorf("%w: %s requires credentials and none were supplied",
			probe.ErrSkipped, meta.Product))
		return obs
	}

	if !probe.HasScheme(t.Address) {
		opts.Warn(t, fmt.Sprintf("address %q has no scheme; assuming %s — run `enodia config resolve` to make this explicit",
			t.Address, schemeOr(meta.DefaultScheme)))
	}
	if t.TLS.Insecure && len(t.TLS.PinSHA256) == 0 {
		opts.Warn(t, "TLS verification is disabled for this service")
	}

	var obs probe.Observation
	attempts := opts.Retries + 1
	for attempt := range attempts {
		if attempt > 0 {
			delay := opts.Backoff * (1 << (attempt - 1))
			delay += time.Duration(rand.Int64N(int64(delay/2 + 1)))
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return failed(t, fmt.Errorf("%w: cancelled", probe.ErrUnreachable))
			}
		}
		obs, err = p.Probe(ctx, t)
		if err == nil {
			obs.Normalized = version.Clean(obs.Version)
			if obs.Edition == "" {
				obs.Edition = version.Edition(obs.Version)
			}
			return obs
		}
		if !probe.Retryable(err) || errors.Is(ctx.Err(), context.Canceled) {
			break
		}
	}

	obs.Kind = "observation"
	obs.ID, obs.Name, obs.Product = t.ID, t.Name, t.Product
	if obs.CollectedAt.IsZero() {
		obs.CollectedAt = time.Now().UTC()
	}
	obs.Error = err.Error()
	obs.ErrorKind = probe.Kind(err)
	return obs
}

func failed(t probe.Target, err error) probe.Observation {
	return probe.Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: time.Now().UTC(),
		Error:       err.Error(), ErrorKind: probe.Kind(err),
	}
}

func schemeOr(s string) string {
	if s == "" {
		return "https"
	}
	return s
}
