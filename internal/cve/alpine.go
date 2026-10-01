// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/EpicMorg/enodia/internal/version"
)

// alpineFix is one secdb secfixes entry: the CVEs fixed in Fixed.
type alpineFix struct {
	Fixed string
	CVEs  []string
}

// alpineSecdb is Alpine's secdb reduced to what matching needs: branch
// ("v3.20") -> origin package -> fixes. main and community merge into one
// branch.
type alpineSecdb map[string]map[string][]alpineFix

var reCVEID = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// LoadAlpineSecdb reads Alpine's secdb JSON (the operator downloads
// https://secdb.alpinelinux.org/<branch>/main.json and community.json
// themselves, see docs/DECISIONS.md D44): one file, or every .json file
// directly inside a directory. Each file names its own branch
// ("distroversion"). A "0" fixed version is secdb's "never affected" and
// is skipped, as are entries citing no CVE id at all (61 of 17,859 in
// v3.20 and v3.22 together, e.g. "ALPINE-13661"); ids like
// "CVE-2021-27219 GHSL-2021-045" keep their CVE.
func LoadAlpineSecdb(path string) (*Index, error) {
	files, err := resolveAlpineFiles(path)
	if err != nil {
		return nil, err
	}
	db := alpineSecdb{}
	for _, f := range files {
		if err := loadAlpineFile(f, db); err != nil {
			return nil, err
		}
	}
	return &Index{byProduct: map[string][]Finding{}, alpine: db}, nil
}

func resolveAlpineFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	matches, err := filepath.Glob(filepath.Join(path, "*.json"))
	if err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("%s: no .json secdb files found", path)
	}
	sort.Strings(matches)
	return matches, nil
}

func loadAlpineFile(path string, db alpineSecdb) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var f struct {
		DistroVersion string `json:"distroversion"`
		Packages      []struct {
			Pkg struct {
				Name     string              `json:"name"`
				Secfixes map[string][]string `json:"secfixes"`
			} `json:"pkg"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	if f.DistroVersion == "" || len(f.Packages) == 0 {
		return fmt.Errorf("%s: no distroversion or packages — is this an Alpine secdb file?", path)
	}
	branch := db[f.DistroVersion]
	if branch == nil {
		branch = map[string][]alpineFix{}
		db[f.DistroVersion] = branch
	}
	for _, p := range f.Packages {
		for fixed, ids := range p.Pkg.Secfixes {
			if fixed == "0" {
				continue
			}
			var cves []string
			for _, id := range ids {
				cves = append(cves, reCVEID.FindAllString(id, -1)...)
			}
			if len(cves) > 0 {
				branch[p.Pkg.Name] = append(branch[p.Pkg.Name], alpineFix{Fixed: fixed, CVEs: cves})
			}
		}
	}
	return nil
}

// lookupAlpine is LookupPackages for product "alpine-linux": q.Packages
// are origin (aport) packages, the name secdb is keyed on; q.Version's
// major.minor picks the branch ("3.20.3" -> "v3.20").
func (idx *Index) lookupAlpine(q PackageQuery) []Finding {
	parts := strings.SplitN(q.Version, ".", 3)
	if len(parts) < 2 {
		return nil
	}
	byPkg := idx.alpine["v"+parts[0]+"."+parts[1]]
	if byPkg == nil {
		return nil
	}
	var out []Finding
	for _, pkg := range slices.Sorted(maps.Keys(q.Packages)) {
		have := q.Packages[pkg]
		agg := packageAggregate{cmp: version.CompareAPK, rank: func(string) int { return 0 }}
		for _, fix := range byPkg[pkg] {
			if version.CompareAPK(have, fix.Fixed) < 0 {
				agg.add(fix.Fixed, "", nil, fix.CVEs...)
			}
		}
		if f, ok := agg.finding("alpine", pkg, have); ok {
			f.AdvisoryID = pkg
			f.AdvisoryURL = "https://security.alpinelinux.org/srcpkg/" + url.PathEscape(pkg)
			out = append(out, f)
		}
	}
	return out
}
