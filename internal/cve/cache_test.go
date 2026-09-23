// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"os"
	"path/filepath"
	"testing"
)

func copySample(t *testing.T, dst string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "sample.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadBDUCachedBuildsThenReuses(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "sample.xml")
	copySample(t, src)
	cacheDir := filepath.Join(dir, "cache")

	var warnings []string
	warn := func(msg string) { warnings = append(warnings, msg) }

	idx1, err := LoadBDUCached(src, cacheDir, warn)
	if err != nil {
		t.Fatalf("first LoadBDUCached: %v", err)
	}
	if got := idx1.Lookup("confluence", "8.3.0"); len(got) != 3 {
		t.Fatalf("got %d findings on first load, want 3", len(got))
	}

	entries, err := os.ReadDir(cacheDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected exactly one cache file to have been written, got %v (err %v)", entries, err)
	}

	// Second load: same source path, same mtime/size — must come from the
	// cache, proven by replacing the file's *content* with something
	// entirely different (a single self-closing valid document, no
	// Confluence entries at all) while explicitly restoring the original
	// mtime and keeping the byte count identical. A from-scratch reparse
	// would see the replacement content and find nothing; only a genuine
	// cache hit still returns the original three findings.
	origInfo, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}
	orig, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	replacement := []byte("<?xml version=\"1.0\"?><vulnerabilities></vulnerabilities>")
	for len(replacement) < len(orig) {
		replacement = append(replacement, ' ')
	}
	if err := os.WriteFile(src, replacement, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(src, origInfo.ModTime(), origInfo.ModTime()); err != nil {
		t.Fatal(err)
	}

	idx2, err := LoadBDUCached(src, cacheDir, warn)
	if err != nil {
		t.Fatalf("second LoadBDUCached (should have served from cache): %v", err)
	}
	if got := idx2.Lookup("confluence", "8.3.0"); len(got) != 3 {
		t.Fatalf("got %d findings from cache, want 3", len(got))
	}
	if got := idx2.Lookup("jira", "8.1.0"); len(got) != 1 {
		t.Fatalf("got %d jira findings from cache, want 1", len(got))
	}
	if len(warnings) != 0 {
		t.Fatalf("got warnings %+v, want none", warnings)
	}
}

func TestLoadBDUCachedRebuildsAfterSourceChanges(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "sample.xml")
	copySample(t, src)
	cacheDir := filepath.Join(dir, "cache")

	if _, err := LoadBDUCached(src, cacheDir, nil); err != nil {
		t.Fatalf("first LoadBDUCached: %v", err)
	}

	// Overwrite with different (but still valid) content and a distinct
	// size, so the cache's mtime+size check is guaranteed to see a change
	// regardless of filesystem mtime granularity.
	if err := os.WriteFile(src, []byte("<?xml version=\"1.0\"?><vulnerabilities></vulnerabilities>\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	idx, err := LoadBDUCached(src, cacheDir, nil)
	if err != nil {
		t.Fatalf("second LoadBDUCached: %v", err)
	}
	if got := idx.Lookup("confluence", "8.3.0"); len(got) != 0 {
		t.Fatalf("got %d findings after the source was replaced with an empty export, want 0 (stale cache was reused)", len(got))
	}
}

func TestLoadBDUCachedMissingSourceErrors(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadBDUCached(filepath.Join(dir, "nope.xml"), filepath.Join(dir, "cache"), nil)
	if err == nil {
		t.Fatal("expected an error for a missing source file")
	}
}

func TestLoadBDUCachedCorruptCacheFallsBackAndWarns(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "sample.xml")
	copySample(t, src)
	cacheDir := filepath.Join(dir, "cache")

	if _, err := LoadBDUCached(src, cacheDir, nil); err != nil {
		t.Fatalf("first LoadBDUCached: %v", err)
	}
	entries, err := os.ReadDir(cacheDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected one cache file, got %v (err %v)", entries, err)
	}
	cachePath := filepath.Join(cacheDir, entries[0].Name())
	if err := os.WriteFile(cachePath, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	var warnings []string
	idx, err := LoadBDUCached(src, cacheDir, func(msg string) { warnings = append(warnings, msg) })
	if err != nil {
		t.Fatalf("LoadBDUCached with a corrupt cache: %v", err)
	}
	if got := idx.Lookup("confluence", "8.3.0"); len(got) != 3 {
		t.Fatalf("got %d findings after falling back past a corrupt cache, want 3", len(got))
	}
	if len(warnings) == 0 {
		t.Fatal("expected a warning about the corrupt cache entry")
	}
}

func copySampleNVD(t *testing.T, dst string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "sample_nvd.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadNVDCachedBuildsThenReuses(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "nvdcve-2.0-2023.json")
	copySampleNVD(t, src)
	cacheDir := filepath.Join(dir, "cache")

	idx1, err := LoadNVDCached(src, cacheDir, nil)
	if err != nil {
		t.Fatalf("first LoadNVDCached: %v", err)
	}
	if got := idx1.Lookup("confluence", "8.3.0"); len(got) != 2 {
		t.Fatalf("got %d findings on first load, want 2", len(got))
	}

	origInfo, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}
	orig, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	replacement := []byte(`{"vulnerabilities":[]}`)
	for len(replacement) < len(orig) {
		replacement = append(replacement, ' ')
	}
	if err := os.WriteFile(src, replacement, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(src, origInfo.ModTime(), origInfo.ModTime()); err != nil {
		t.Fatal(err)
	}

	idx2, err := LoadNVDCached(src, cacheDir, nil)
	if err != nil {
		t.Fatalf("second LoadNVDCached (should have served from cache): %v", err)
	}
	if got := idx2.Lookup("confluence", "8.3.0"); len(got) != 2 {
		t.Fatalf("got %d findings from cache, want 2", len(got))
	}
}

// A directory source's cache must invalidate when a new file is added,
// not just when an existing one's mtime/size changes — the set of paths
// contributing to the index is itself part of the cache's freshness
// signal.
func TestLoadNVDCachedDirectoryInvalidatesWhenFileAdded(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "nvdcve-2.0-2023.json")
	copySampleNVD(t, src)
	cacheDir := filepath.Join(dir, "cache")

	idx1, err := LoadNVDCached(dir, cacheDir, nil)
	if err != nil {
		t.Fatalf("first LoadNVDCached: %v", err)
	}
	if got := idx1.Lookup("confluence", "8.3.0"); len(got) != 2 {
		t.Fatalf("got %d findings on first load, want 2", len(got))
	}

	copySampleNVD(t, filepath.Join(dir, "nvdcve-2.0-2024.json"))

	idx2, err := LoadNVDCached(dir, cacheDir, nil)
	if err != nil {
		t.Fatalf("second LoadNVDCached: %v", err)
	}
	// Both files carry the same fixture, so a correct rebuild doubles the
	// finding count; a stale cache hit would still report 2.
	if got := idx2.Lookup("confluence", "8.3.0"); len(got) != 4 {
		t.Fatalf("got %d findings after adding a second file, want 4 (cache should have invalidated)", len(got))
	}
}

func TestMergeIndexCombinesBothSources(t *testing.T) {
	bduIdx, err := LoadBDU(filepath.Join("testdata", "sample.xml"))
	if err != nil {
		t.Fatalf("LoadBDU: %v", err)
	}
	nvdIdx, err := LoadNVD(filepath.Join("testdata", "sample_nvd.json"))
	if err != nil {
		t.Fatalf("LoadNVD: %v", err)
	}

	merged := MergeIndex(bduIdx, nvdIdx)
	got := merged.Lookup("confluence", "8.3.0")
	var sources = map[string]int{}
	for _, f := range got {
		sources[f.Source]++
	}
	if sources["bdu"] == 0 || sources["nvd"] == 0 {
		t.Fatalf("got sources %+v, want findings from both bdu and nvd", sources)
	}
}

func TestMergeIndexNilSafe(t *testing.T) {
	if got := MergeIndex(nil, nil); got != nil {
		t.Fatalf("got %+v, want nil", got)
	}
	idx, err := LoadBDU(filepath.Join("testdata", "sample.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if got := MergeIndex(idx, nil); got != idx {
		t.Fatal("MergeIndex(idx, nil) should return idx unchanged")
	}
	if got := MergeIndex(nil, idx); got != idx {
		t.Fatal("MergeIndex(nil, idx) should return idx unchanged")
	}
}
