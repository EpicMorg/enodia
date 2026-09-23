// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DefaultCacheDir returns the on-disk cache location for a parsed BDU
// index — the same OS-cache-directory convention resolver.Cache already
// uses (os.UserCacheDir(), not /tmp: this is regenerable but worth
// surviving between runs, not throwaway).
func DefaultCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("determining cache directory: %w", err)
	}
	return filepath.Join(base, "enodia", "cve"), nil
}

// cachedFinding is Finding minus its unexported, unserializable rng field.
// Re-parsing RangeText on load is cheap (a single regex match against an
// already-filtered, small set of findings) and guaranteed to succeed
// again, since it already succeeded once to get into the cache — so there
// is no need to serialize bduRange itself.
type cachedFinding struct {
	BDUID     string
	CVEIDs    []string
	Title     string
	Severity  string
	SoftName  string
	RangeText string
	FixStatus string
}

type cacheFile struct {
	SourceModTime time.Time
	SourceSize    int64
	ByProduct     map[string][]cachedFinding
}

// cachePathFor derives a stable, collision-resistant cache filename from
// sourcePath — hashed rather than sanitized-and-embedded, since a real
// path can carry characters no filename convention needs to worry about.
func cachePathFor(cacheDir, sourcePath string) string {
	sum := sha256.Sum256([]byte(sourcePath))
	return filepath.Join(cacheDir, fmt.Sprintf("bdu-%x.json", sum[:8]))
}

// LoadBDUCached is the normal entry point: it reuses a cached index built
// from an earlier run of this exact sourcePath, as long as the file's own
// mtime and size still match what the cache was built from, and falls
// back to a full LoadBDU (then writes the result back) otherwise.
//
// No TTL, unlike resolver.Cache: that cache fronts a live HTTP source
// that changes on its own schedule, so a cache entry needs an expiry even
// if nothing here asks for a refresh. This one fronts a local file the
// operator manages entirely themselves (see docs/DECISIONS.md D30) — its
// own mtime is already the correct, exact invalidation signal, and adding
// a TTL on top would just mean silently serving a stale answer between
// TTL expiry and the operator's next real update, or the reverse.
//
// warn, if non-nil, is called for a cache read/write problem that doesn't
// stop the load from succeeding (a corrupt or unwritable cache entry) —
// the same non-fatal-notice shape used across this project (resolver.Cache,
// internal/collect).
func LoadBDUCached(sourcePath, cacheDir string, warn func(string)) (*Index, error) {
	if warn == nil {
		warn = func(string) {}
	}

	info, err := os.Stat(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", sourcePath, err)
	}

	cp := cachePathFor(cacheDir, sourcePath)
	if idx := tryLoadCache(cp, info, warn); idx != nil {
		return idx, nil
	}

	idx, err := LoadBDU(sourcePath)
	if err != nil {
		return nil, err
	}
	if err := writeCache(cp, info, idx); err != nil {
		warn(fmt.Sprintf("cve cache: %v", err))
	}
	return idx, nil
}

func tryLoadCache(cachePath string, info os.FileInfo, warn func(string)) *Index {
	raw, err := os.ReadFile(cachePath)
	if err != nil {
		return nil // no cache yet — not an error worth a warning
	}
	var cf cacheFile
	if err := json.Unmarshal(raw, &cf); err != nil {
		warn(fmt.Sprintf("cve cache: %s is corrupt, rebuilding: %v", cachePath, err))
		return nil
	}
	if !cf.SourceModTime.Equal(info.ModTime()) || cf.SourceSize != info.Size() {
		return nil // source file changed since this cache was built
	}

	idx := &Index{byProduct: make(map[string][]Finding, len(cf.ByProduct))}
	for product, findings := range cf.ByProduct {
		out := make([]Finding, 0, len(findings))
		for _, cfF := range findings {
			rng, ok := parseBDUVersion(cfF.RangeText)
			if !ok {
				// Cannot happen for a cache this package itself wrote —
				// RangeText only ever got in because it parsed once
				// already — but a hand-edited or foreign cache file isn't
				// impossible, and silently keeping a zero-value range
				// would be a wrong verdict, not a missing one.
				warn(fmt.Sprintf("cve cache: %s: %s: %q no longer parses as a version, dropping this entry", cachePath, cfF.BDUID, cfF.RangeText))
				continue
			}
			out = append(out, Finding{
				BDUID: cfF.BDUID, CVEIDs: cfF.CVEIDs, Title: cfF.Title,
				Severity: cfF.Severity, SoftName: cfF.SoftName,
				RangeText: cfF.RangeText, FixStatus: cfF.FixStatus, rng: rng,
			})
		}
		idx.byProduct[product] = out
	}
	return idx
}

func writeCache(cachePath string, info os.FileInfo, idx *Index) error {
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o700); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}

	cf := cacheFile{
		SourceModTime: info.ModTime(),
		SourceSize:    info.Size(),
		ByProduct:     make(map[string][]cachedFinding, len(idx.byProduct)),
	}
	for product, findings := range idx.byProduct {
		out := make([]cachedFinding, len(findings))
		for i, f := range findings {
			out[i] = cachedFinding{
				BDUID: f.BDUID, CVEIDs: f.CVEIDs, Title: f.Title,
				Severity: f.Severity, SoftName: f.SoftName,
				RangeText: f.RangeText, FixStatus: f.FixStatus,
			}
		}
		cf.ByProduct[product] = out
	}

	raw, err := json.Marshal(cf)
	if err != nil {
		return fmt.Errorf("encoding cache: %w", err)
	}
	if err := os.WriteFile(cachePath, raw, 0o600); err != nil {
		return fmt.Errorf("writing cache: %w", err)
	}
	return nil
}
