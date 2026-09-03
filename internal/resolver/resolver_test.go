// SPDX-License-Identifier: AGPL-3.0-or-later

package resolver

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/EpicMorg/enodia/internal/probe"
)

type countingSource struct {
	calls  int
	cycles []Cycle
	err    error
}

func (s *countingSource) Fetch(context.Context, probe.ResolverRef) ([]Cycle, error) {
	s.calls++
	return s.cycles, s.err
}

func TestResolveEmptyTypeIsNotAnError(t *testing.T) {
	r := &Resolver{}
	cycles, err := r.Resolve(context.Background(), probe.ResolverRef{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cycles != nil {
		t.Fatalf("got %v, want nil", cycles)
	}
}

func TestResolveUnsupportedTypeErrors(t *testing.T) {
	r := &Resolver{Sources: map[string]Source{}}
	_, err := r.Resolve(context.Background(), probe.ResolverRef{Type: "carrier-pigeon", ID: "x"})
	if !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("got %v, want ErrUnsupportedType", err)
	}
}

func TestResolveFetchesFromSourceAndCaches(t *testing.T) {
	src := &countingSource{cycles: []Cycle{{Cycle: "1.0", Latest: "1.0.1"}}}
	cache := &Cache{Dir: t.TempDir(), TTL: time.Hour}
	r := &Resolver{Cache: cache, Sources: map[string]Source{"fake": src}}

	ref := probe.ResolverRef{Type: "fake", ID: "widget"}
	cycles, err := r.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(cycles) != 1 || cycles[0].Cycle != "1.0" {
		t.Fatalf("got %+v", cycles)
	}
	if src.calls != 1 {
		t.Fatalf("source called %d times, want 1", src.calls)
	}

	if _, hit, err := cache.Load(ref, time.Now()); err != nil || !hit {
		t.Fatalf("expected Resolve to populate the cache: hit=%v err=%v", hit, err)
	}
}

func TestResolveUsesFreshCacheWithoutCallingSource(t *testing.T) {
	src := &countingSource{cycles: []Cycle{{Cycle: "should-not-be-returned"}}}
	cache := &Cache{Dir: t.TempDir(), TTL: time.Hour}
	ref := probe.ResolverRef{Type: "fake", ID: "widget"}
	if err := cache.Store(ref, []Cycle{{Cycle: "from-cache"}}, time.Now()); err != nil {
		t.Fatal(err)
	}

	r := &Resolver{Cache: cache, Sources: map[string]Source{"fake": src}}
	cycles, err := r.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(cycles) != 1 || cycles[0].Cycle != "from-cache" {
		t.Fatalf("got %+v, want the cached entry", cycles)
	}
	if src.calls != 0 {
		t.Fatalf("source called %d times, want 0 (cache should have short-circuited it)", src.calls)
	}
}

func TestResolveRefetchesAfterCacheExpires(t *testing.T) {
	src := &countingSource{cycles: []Cycle{{Cycle: "fresh"}}}
	cache := &Cache{Dir: t.TempDir(), TTL: time.Minute}
	ref := probe.ResolverRef{Type: "fake", ID: "widget"}
	stale := time.Now().Add(-time.Hour)
	if err := cache.Store(ref, []Cycle{{Cycle: "stale"}}, stale); err != nil {
		t.Fatal(err)
	}

	r := &Resolver{Cache: cache, Sources: map[string]Source{"fake": src}}
	cycles, err := r.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(cycles) != 1 || cycles[0].Cycle != "fresh" {
		t.Fatalf("got %+v, want the freshly fetched entry", cycles)
	}
	if src.calls != 1 {
		t.Fatalf("source called %d times, want 1", src.calls)
	}
}

func TestResolveSourceErrorPropagates(t *testing.T) {
	src := &countingSource{err: ErrUnreachable}
	r := &Resolver{Sources: map[string]Source{"fake": src}}
	_, err := r.Resolve(context.Background(), probe.ResolverRef{Type: "fake", ID: "widget"})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}
}

func TestResolveWarnsOnCorruptCacheButStillResolves(t *testing.T) {
	dir := t.TempDir()
	cache := &Cache{Dir: dir, TTL: time.Hour}
	ref := probe.ResolverRef{Type: "fake", ID: "widget"}
	if err := os.WriteFile(cache.path(ref), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	src := &countingSource{cycles: []Cycle{{Cycle: "recovered"}}}
	var warnings []string
	r := &Resolver{
		Cache:   cache,
		Sources: map[string]Source{"fake": src},
		Warn:    func(msg string) { warnings = append(warnings, msg) },
	}

	cycles, err := r.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(cycles) != 1 || cycles[0].Cycle != "recovered" {
		t.Fatalf("got %+v", cycles)
	}
	if len(warnings) == 0 {
		t.Fatal("expected a warning about the corrupt cache entry")
	}
}

func TestNewWiresEndoflifeAndGithubSources(t *testing.T) {
	r := New(nil)
	if _, ok := r.Sources["endoflife"]; !ok {
		t.Fatal("expected an \"endoflife\" source")
	}
	if _, ok := r.Sources["github"]; !ok {
		t.Fatal("expected a \"github\" source")
	}
}
