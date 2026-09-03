// SPDX-License-Identifier: AGPL-3.0-or-later

// Package serve implements `enodia serve`: a snapshot-only HTTP server.
//
// D14 is the whole design, verbatim: "a ticker goroutine collects, and
// handlers read a snapshot pointer. No polling on request, ever." A request
// never triggers a new collection — that would make the monitoring tool a
// denial-of-service risk against the very fleet it watches. There is no
// built-in authentication or TLS here; this is meant to run behind a
// reverse proxy, which owns both (deliberately not planned otherwise).
package serve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/EpicMorg/enodia/internal/render"
)

// Collector produces one fresh render.Report. cmd/enodia supplies this,
// wrapping its usual config-load -> collect -> resolve -> evaluate
// pipeline: this package knows nothing about config, collect or resolver,
// only about serving whatever a Collector last produced.
type Collector func(ctx context.Context) (render.Report, error)

// Options configures Run.
type Options struct {
	Addr     string        // e.g. ":8080"
	Interval time.Duration // how often Collector runs again; must be > 0

	// Warn (optional) receives non-fatal notices — a refresh cycle failed
	// and the previous snapshot is being kept, e.g.
	Warn func(msg string)
}

func (o Options) warn(msg string) {
	if o.Warn != nil {
		o.Warn(msg)
	}
}

// store holds the most recent snapshot for handlers to read. Swapped
// atomically so a refresh cycle updating it never blocks, or races with, a
// request being served concurrently.
type store struct {
	current atomic.Pointer[render.Report]
}

func (s *store) Load() *render.Report  { return s.current.Load() }
func (s *store) Store(r render.Report) { s.current.Store(&r) }

// Run collects once synchronously — so the server never starts with nothing
// to show — then serves on opts.Addr while a background ticker refreshes
// the snapshot every opts.Interval. It blocks until ctx is canceled, then
// shuts the server down gracefully and returns.
func Run(ctx context.Context, collect Collector, opts Options) error {
	if opts.Interval <= 0 {
		return fmt.Errorf("serve: Interval must be positive, got %s", opts.Interval)
	}

	st := &store{}
	report, err := collect(ctx)
	if err != nil {
		return fmt.Errorf("initial collection: %w", err)
	}
	st.Store(report)

	srv := &http.Server{
		Addr:              opts.Addr,
		Handler:           newMux(st),
		ReadHeaderTimeout: 10 * time.Second, // a slow client must not tie up a handler goroutine forever
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()

	ticker := time.NewTicker(opts.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Deliberately not derived from ctx: it is already Done, and
			// Shutdown needs its own grace period to drain in-flight
			// requests rather than aborting them immediately.
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return srv.Shutdown(shutdownCtx) //nolint:contextcheck // shutdownCtx is deliberately not derived from the already-Done ctx

		case err := <-serveErr:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return fmt.Errorf("http server: %w", err)

		case <-ticker.C:
			report, err := collect(ctx)
			if err != nil {
				opts.warn(fmt.Sprintf("refresh cycle failed, keeping the previous snapshot: %v", err))
				continue
			}
			st.Store(report)
		}
	}
}
