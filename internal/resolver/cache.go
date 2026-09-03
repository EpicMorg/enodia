// SPDX-License-Identifier: AGPL-3.0-or-later

package resolver

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/EpicMorg/enodia/internal/probe"
)

// Cache persists resolved cycles on disk, keyed by resolver ref, with a TTL.
type Cache struct {
	Dir string
	TTL time.Duration
}

// DefaultCacheDir returns the default on-disk cache location, following the
// OS's usual convention for non-essential, regenerable data.
func DefaultCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("determining cache directory: %w", err)
	}
	return filepath.Join(base, "enodia", "resolver"), nil
}

type cacheEntry struct {
	FetchedAt time.Time `json:"fetchedAt"`
	Cycles    []Cycle   `json:"cycles"`
}

// Load returns the cached cycles for ref if a fresh entry exists.
//
// hit is false both when there is no entry yet and when there is one but it
// has aged past TTL — in neither case is err set. err is non-nil only for a
// genuine read or decode failure, which the caller should treat as a
// warning: a broken cache is a reason to re-fetch, not to fail resolution.
func (c Cache) Load(ref probe.ResolverRef, now time.Time) (cycles []Cycle, hit bool, err error) {
	path := c.path(ref)
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("reading %s: %w", path, err)
	}

	var entry cacheEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return nil, false, fmt.Errorf("parsing %s: %w", path, err)
	}
	if now.Sub(entry.FetchedAt) > c.TTL {
		return nil, false, nil
	}
	return entry.Cycles, true, nil
}

// Store writes cycles to the cache, stamped with fetchedAt.
func (c Cache) Store(ref probe.ResolverRef, cycles []Cycle, fetchedAt time.Time) error {
	if err := os.MkdirAll(c.Dir, 0o755); err != nil {
		return fmt.Errorf("creating cache dir %s: %w", c.Dir, err)
	}
	raw, err := json.Marshal(cacheEntry{FetchedAt: fetchedAt, Cycles: cycles})
	if err != nil {
		return fmt.Errorf("encoding cache entry: %w", err)
	}

	path := c.path(ref)
	// Write to a temp file and rename so a crash mid-write never leaves a
	// half-written entry for Load to choke on next time.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("renaming %s to %s: %w", tmp, path, err)
	}
	return nil
}

// path turns a ref into a single, safe filename. QueryEscape rules out any
// "/" or ".." finding its way into the path, which matters because a
// GitHub-style ref.ID ("owner/repo") is exactly the kind of value that would
// otherwise create an unwanted subdirectory.
func (c Cache) path(ref probe.ResolverRef) string {
	return filepath.Join(c.Dir, url.QueryEscape(ref.Type+":"+ref.ID)+".json")
}
