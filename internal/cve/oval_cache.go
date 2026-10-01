// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// ovalCacheFormat is bumped whenever what an ovalRelease carries, or how
// an OVAL file is read into one, changes.
const ovalCacheFormat = 2

// ovalCacheFile is one OVAL file's extracted fixes, stored as data: the
// advisories once, each fix pointing at its own by index.
type ovalCacheFile struct {
	Format     int
	Source     fileSignature
	Key        string
	Advisories []ovalAdvisory
	Fixes      []ovalCachedFix
	Kernels    []ovalCachedKernel
}

type ovalCachedFix struct {
	Package, Fixed, Module, Arch, Variant string
	Adv                                   int
}

type ovalCachedKernel struct {
	Flavour, Pattern, Fixed string
	Adv                     int
}

// LoadOVALCached is LoadOVAL fronted by an on-disk cache, one entry per
// OVAL file, invalidated by that file's own mtime and size — the same rule
// as the BDU and NVD caches (see loadCached). Measured: parsing Ubuntu
// noble's, RHEL 9's, AlmaLinux 9's and Oracle Linux 9's files takes ~10s
// together, most of it bzip2; a fleet with a few releases of each would
// pay that on every run.
func LoadOVALCached(path, cacheDir string, warn func(string)) (*Index, error) {
	if warn == nil {
		warn = func(string) {}
	}
	return loadOVALWith(path, func(file string) (string, *ovalRelease, error) {
		sigs, err := statAll([]string{file})
		if err != nil {
			return "", nil, err
		}
		cp := cachePathFor(cacheDir, "oval", []string{file})
		if key, rel := tryLoadOVALCache(cp, sigs[0], warn); rel != nil {
			return key, rel, nil
		}
		key, rel, err := loadOVALFile(file)
		if err != nil {
			return "", nil, err
		}
		if err := writeOVALCache(cp, sigs[0], key, rel); err != nil {
			warn(fmt.Sprintf("oval cache: %v", err))
		}
		return key, rel, nil
	})
}

func tryLoadOVALCache(cachePath string, sig fileSignature, warn func(string)) (string, *ovalRelease) {
	raw, err := os.ReadFile(cachePath)
	if err != nil {
		return "", nil
	}
	var cf ovalCacheFile
	if err := json.Unmarshal(raw, &cf); err != nil {
		warn(fmt.Sprintf("oval cache: %s is corrupt, rebuilding: %v", cachePath, err))
		return "", nil
	}
	if cf.Format != ovalCacheFormat || !sameSignatures([]fileSignature{cf.Source}, []fileSignature{sig}) {
		return "", nil
	}
	advs := make([]*ovalAdvisory, len(cf.Advisories))
	for i := range cf.Advisories {
		advs[i] = &cf.Advisories[i]
	}
	adv := func(i int) *ovalAdvisory {
		if i >= 0 && i < len(advs) {
			return advs[i]
		}
		return &ovalAdvisory{}
	}
	rel := &ovalRelease{fixes: map[string][]ovalFix{}}
	for _, f := range cf.Fixes {
		rel.fixes[f.Package] = append(rel.fixes[f.Package], ovalFix{Package: f.Package, Fixed: f.Fixed, Module: f.Module, Arch: f.Arch, Variant: f.Variant, adv: adv(f.Adv)})
	}
	for _, k := range cf.Kernels {
		re, err := regexp.Compile(k.Pattern)
		if err != nil {
			warn(fmt.Sprintf("oval cache: %s is corrupt, rebuilding: %v", cachePath, err))
			return "", nil
		}
		rel.kernels = append(rel.kernels, ovalKernelFix{Flavour: k.Flavour, Pattern: re, Fixed: k.Fixed, adv: adv(k.Adv)})
	}
	return cf.Key, rel
}

func writeOVALCache(cachePath string, sig fileSignature, key string, rel *ovalRelease) error {
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o700); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}
	cf := ovalCacheFile{Format: ovalCacheFormat, Source: sig, Key: key}
	advIdx := map[*ovalAdvisory]int{}
	index := func(a *ovalAdvisory) int {
		if i, ok := advIdx[a]; ok {
			return i
		}
		advIdx[a] = len(cf.Advisories)
		cf.Advisories = append(cf.Advisories, *a)
		return advIdx[a]
	}
	for _, fixes := range rel.fixes {
		for _, f := range fixes {
			cf.Fixes = append(cf.Fixes, ovalCachedFix{Package: f.Package, Fixed: f.Fixed, Module: f.Module, Arch: f.Arch, Variant: f.Variant, Adv: index(f.adv)})
		}
	}
	for _, k := range rel.kernels {
		cf.Kernels = append(cf.Kernels, ovalCachedKernel{Flavour: k.Flavour, Pattern: k.Pattern.String(), Fixed: k.Fixed, Adv: index(k.adv)})
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
