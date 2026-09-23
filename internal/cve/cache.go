// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// DefaultCacheDir returns the on-disk cache location for a parsed cve
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

// cachedFinding is Finding minus its unexported rng field, plus Rng
// itself, exported and directly serializable (a versionRange is just
// []int/bool fields) — stored as data rather than re-derived from
// RangeText on load, so a cache load never has to re-run either source's
// own text/JSON parsing logic and can never disagree with what was
// actually indexed.
type cachedFinding struct {
	Source      string
	AdvisoryID  string
	CVEIDs      []string
	Title       string
	Severity    string
	MatchedName string
	RangeText   string
	FixStatus   string
	Rng         versionRange
}

// fileSignature is one source file's identity as of the run that built a
// cache entry: its path plus mtime and size, the same freshness signal
// resolver-free local-file sources use throughout this package. A cache
// entry can rest on more than one file (LoadNVDCached, given a directory
// of yearly archives) — every one of them has to still match, and the set
// of paths itself has to be unchanged, for the cache to still apply.
type fileSignature struct {
	Path    string
	ModTime time.Time
	Size    int64
}

type cacheFile struct {
	Sources   []fileSignature
	ByProduct map[string][]cachedFinding
}

// cachePathFor derives a stable, collision-resistant cache filename from
// kind (a short source tag, e.g. "bdu" or "nvd") and paths — hashed rather
// than sanitized-and-embedded, since a real path can carry characters no
// filename convention needs to worry about, and a multi-file source can
// have arbitrarily many of them.
func cachePathFor(cacheDir, kind string, paths []string) string {
	h := sha256.New()
	for _, p := range paths {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	return filepath.Join(cacheDir, fmt.Sprintf("%s-%x.json", kind, h.Sum(nil)[:8]))
}

func statAll(paths []string) ([]fileSignature, error) {
	sorted := append([]string(nil), paths...)
	sort.Strings(sorted)
	sigs := make([]fileSignature, len(sorted))
	for i, p := range sorted {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", p, err)
		}
		sigs[i] = fileSignature{Path: p, ModTime: info.ModTime(), Size: info.Size()}
	}
	return sigs, nil
}

func sameSignatures(a, b []fileSignature) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Path != b[i].Path || a[i].Size != b[i].Size || !a[i].ModTime.Equal(b[i].ModTime) {
			return false
		}
	}
	return true
}

// loadCached is the shared machinery behind LoadBDUCached and
// LoadNVDCached: reuse a cached Index built from an earlier run over the
// exact same set of source files, as long as every one of them still has
// the mtime and size the cache was built from, and fall back to a full
// load (then write the result back) otherwise.
//
// No TTL, unlike resolver.Cache: that cache fronts a live HTTP source that
// changes on its own schedule, so a cache entry needs an expiry even if
// nothing here asks for a refresh. This one fronts local files the
// operator manages entirely themselves (see docs/DECISIONS.md D30/D31) —
// their own mtime is already the correct, exact invalidation signal, and
// adding a TTL on top would just mean silently serving a stale answer
// between TTL expiry and the operator's next real update, or the reverse.
//
// warn, if non-nil, is called for a cache read/write problem that doesn't
// stop the load from succeeding (a corrupt or unwritable cache entry) —
// the same non-fatal-notice shape used across this project (resolver.Cache,
// internal/collect).
func loadCached(kind string, paths []string, load func([]string) (*Index, error), cacheDir string, warn func(string)) (*Index, error) {
	if warn == nil {
		warn = func(string) {}
	}

	sigs, err := statAll(paths)
	if err != nil {
		return nil, err
	}

	cp := cachePathFor(cacheDir, kind, paths)
	if idx := tryLoadCache(cp, sigs, warn); idx != nil {
		return idx, nil
	}

	idx, err := load(paths)
	if err != nil {
		return nil, err
	}
	if err := writeCache(cp, sigs, idx); err != nil {
		warn(fmt.Sprintf("cve cache: %v", err))
	}
	return idx, nil
}

// LoadBDUCached is LoadBDU fronted by loadCached's on-disk cache.
func LoadBDUCached(sourcePath, cacheDir string, warn func(string)) (*Index, error) {
	return loadCached("bdu", []string{sourcePath}, func(paths []string) (*Index, error) {
		return LoadBDU(paths[0])
	}, cacheDir, warn)
}

// LoadNVDCached is LoadNVD fronted by loadCached's on-disk cache. path may
// name a single file or a directory of them, exactly as LoadNVD accepts —
// resolved to the concrete file list first, so the cache also invalidates
// itself when a new yearly archive is added to (or one removed from) the
// directory, not just when an existing one changes.
func LoadNVDCached(path, cacheDir string, warn func(string)) (*Index, error) {
	files, err := resolveNVDFiles(path)
	if err != nil {
		return nil, err
	}
	return loadCached("nvd", files, func(paths []string) (*Index, error) {
		idx := &Index{byProduct: make(map[string][]Finding)}
		cpeToProduct := make(map[cpeName]string, len(productCPENames)*2)
		for product, names := range productCPENames {
			for _, n := range names {
				cpeToProduct[n] = product
			}
		}
		for _, p := range paths {
			if err := loadNVDFile(p, idx, cpeToProduct); err != nil {
				return nil, err
			}
		}
		return idx, nil
	}, cacheDir, warn)
}

func tryLoadCache(cachePath string, sigs []fileSignature, warn func(string)) *Index {
	raw, err := os.ReadFile(cachePath)
	if err != nil {
		return nil // no cache yet — not an error worth a warning
	}
	var cf cacheFile
	if err := json.Unmarshal(raw, &cf); err != nil {
		warn(fmt.Sprintf("cve cache: %s is corrupt, rebuilding: %v", cachePath, err))
		return nil
	}
	if !sameSignatures(cf.Sources, sigs) {
		return nil // a source file changed, was added, or was removed since this cache was built
	}

	idx := &Index{byProduct: make(map[string][]Finding, len(cf.ByProduct))}
	for product, findings := range cf.ByProduct {
		out := make([]Finding, 0, len(findings))
		for _, cfF := range findings {
			out = append(out, Finding{
				Source: cfF.Source, AdvisoryID: cfF.AdvisoryID, CVEIDs: cfF.CVEIDs,
				Title: cfF.Title, Severity: cfF.Severity, MatchedName: cfF.MatchedName,
				RangeText: cfF.RangeText, FixStatus: cfF.FixStatus, rng: cfF.Rng,
			})
		}
		idx.byProduct[product] = out
	}
	return idx
}

func writeCache(cachePath string, sigs []fileSignature, idx *Index) error {
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o700); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}

	cf := cacheFile{
		Sources:   sigs,
		ByProduct: make(map[string][]cachedFinding, len(idx.byProduct)),
	}
	for product, findings := range idx.byProduct {
		out := make([]cachedFinding, len(findings))
		for i, f := range findings {
			out[i] = cachedFinding{
				Source: f.Source, AdvisoryID: f.AdvisoryID, CVEIDs: f.CVEIDs,
				Title: f.Title, Severity: f.Severity, MatchedName: f.MatchedName,
				RangeText: f.RangeText, FixStatus: f.FixStatus, Rng: f.rng,
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
