// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cveupdate downloads the files the cve.*.path entries name — the
// only code in enodia that fetches vulnerability data, run only by `enodia
// cve update` (see docs/DECISIONS.md D73). Every other command reads the
// files offline, as before.
package cveupdate

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/EpicMorg/enodia/internal/cve"
)

// Paths are the resolved cve.*.path entries; "" is not configured.
type Paths struct {
	BDU, NVD, Debian, OVAL, Alpine, MariaDB, Atlassian, PostgreSQL, Nginx string
}

// Wants are the per-release files worth fetching, beyond those already on
// disk: OVAL releases ("ubuntu:noble", "rhel:9"), Alpine branches
// ("v3.22") and PostgreSQL majors ("13", "9.6").
type Wants struct {
	OVAL, Alpine, PostgreSQL []string
}

// Item is one file to download.
type Item struct {
	Source string // the cve.<source>.path it belongs to
	URL    string
	Dest   string
	check  func(path string) error
	// replaces are older copies of the same data under other names,
	// removed once Dest is in place.
	replaces []string
}

// nvdFirstYear is NVD's oldest yearly feed.
const nvdFirstYear = 2002

const (
	bduURL       = "https://bdu.fstec.ru/files/documents/vulxml.zip"
	nvdURL       = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-%d.json.gz"
	debianURL    = "https://security-tracker.debian.org/tracker/data/json"
	alpineURL    = "https://secdb.alpinelinux.org/%s/%s.json"
	mariadbURL   = "https://mariadb.com/docs/server/security/cve/community-server.md"
	atlassianURL = "https://api.atlassian.com/vuln-transparency/v1/products"
	pgURL        = "https://www.postgresql.org/support/security/"
	nginxURL     = "https://nginx.org/en/security_advisories.html"
)

// ovalSources maps an OVAL release's product to its vendor's file: the
// URL for a release, the file name it's saved as, and the pattern that
// recognises that name in cve.oval.path. Rocky hosts are matched against
// Red Hat's file (D43), so rocky-linux is an alias of rhel.
var ovalSources = map[string]struct {
	release *regexp.Regexp
	url     func(rel string) string
	name    func(rel string) string
	file    *regexp.Regexp
}{
	"ubuntu": {
		regexp.MustCompile(`^[a-z]+$`),
		func(r string) string {
			return "https://security-metadata.canonical.com/oval/com.ubuntu." + r + ".usn.oval.xml.bz2"
		},
		func(r string) string { return "com.ubuntu." + r + ".usn.oval.xml.bz2" },
		regexp.MustCompile(`^com\.ubuntu\.([a-z]+)\.usn\.oval\.xml(?:\.bz2)?$`),
	},
	"rhel": {
		regexp.MustCompile(`^\d+$`),
		func(r string) string {
			return "https://security.access.redhat.com/data/oval/v2/RHEL" + r + "/rhel-" + r + ".oval.xml.bz2"
		},
		func(r string) string { return "rhel-" + r + ".oval.xml.bz2" },
		regexp.MustCompile(`^rhel-(\d+)\.oval\.xml(?:\.bz2)?$`),
	},
	"almalinux": {
		regexp.MustCompile(`^\d+$`),
		func(r string) string {
			return "https://security.almalinux.org/oval/org.almalinux.alsa-" + r + ".xml.bz2"
		},
		func(r string) string { return "org.almalinux.alsa-" + r + ".xml.bz2" },
		regexp.MustCompile(`^org\.almalinux\.alsa-(\d+)\.xml(?:\.bz2)?$`),
	},
	"oracle-linux": {
		regexp.MustCompile(`^\d+$`),
		func(r string) string {
			return "https://linux.oracle.com/security/oval/com.oracle.elsa-ol" + r + ".xml.bz2"
		},
		func(r string) string { return "com.oracle.elsa-ol" + r + ".xml.bz2" },
		regexp.MustCompile(`^com\.oracle\.elsa-ol(\d+)\.xml(?:\.bz2)?$`),
	},
	"astra-linux": {
		regexp.MustCompile(`^\d+\.\d+$`),
		func(r string) string {
			return "https://dl.astralinux.ru/astra/oval/" + r + "_x86-64/oval-definitions-alse-" + r + ".xml"
		},
		func(r string) string { return "oval-definitions-alse-" + r + ".xml" },
		regexp.MustCompile(`^oval-definitions-alse-(\d+\.\d+)\.xml$`),
	},
	// RED OS names every release's file redos.xml; saved per release.
	"redos": {
		regexp.MustCompile(`^\d+\.\d+$`),
		func(r string) string { return "https://redos.red-soft.ru/support/secure/" + r + "/redos.xml" },
		func(r string) string { return "redos-" + r + ".xml" },
		regexp.MustCompile(`^redos-(\d+\.\d+)\.xml$`),
	},
}

var ovalAliases = map[string]string{"rocky-linux": "rhel", "rocky": "rhel", "alma": "almalinux", "oracle": "oracle-linux", "ol": "oracle-linux", "astra": "astra-linux"}

var (
	alpineBranch = regexp.MustCompile(`^v\d+\.\d+$`)
	alpineFile   = regexp.MustCompile(`^(v\d+\.\d+)-(?:main|community)\.json$`)
	pgMajor      = regexp.MustCompile(`^(?:\d{2,}|[6-9]\.\d)$`)
	pgFile       = regexp.MustCompile(`^(\d{2,}|[6-9]\.\d)\.html$`)
)

// pgMainName is the main security page's name inside a PostgreSQL
// directory.
const pgMainName = "security.html"

// Plan lists the downloads for the configured paths: every file the
// config names, the NVD years to refresh (this one and the last, and any
// year not on disk yet; every year with allYears), and the OVAL releases,
// Alpine branches and PostgreSQL majors in w or already on disk. Problems
// with one source are returned and don't stop the others.
func Plan(p Paths, w Wants, now time.Time, allYears bool) ([]Item, []error) {
	var items []Item
	var errs []error
	add := func(source, url, dest string, check func(string) error) {
		items = append(items, Item{Source: source, URL: url, Dest: dest, check: check})
	}
	load := func(f func(string) (*cve.Index, error)) func(string) error {
		return func(path string) error { _, err := f(path); return err }
	}

	if p.BDU != "" {
		if !strings.EqualFold(filepath.Ext(p.BDU), ".zip") {
			errs = append(errs, fmt.Errorf("cve.bdu.path %s: cve update downloads BDU's own .zip; point the path at a .zip file", p.BDU))
		} else {
			add("bdu", bduURL, p.BDU, load(cve.LoadBDU))
		}
	}

	if p.NVD != "" {
		if !isDir(p.NVD) {
			errs = append(errs, fmt.Errorf("cve.nvd.path %s: cve update needs a directory for NVD's yearly files", p.NVD))
		} else {
			for y := nvdFirstYear; y <= now.Year(); y++ {
				dest := filepath.Join(p.NVD, fmt.Sprintf("nvdcve-2.0-%d.json.gz", y))
				if allYears || y >= now.Year()-1 || !exists(dest) {
					add("nvd", fmt.Sprintf(nvdURL, y), dest, load(cve.LoadNVD))
				}
			}
		}
	}

	if p.Debian != "" {
		if !strings.EqualFold(filepath.Ext(p.Debian), ".json") {
			errs = append(errs, fmt.Errorf("cve.debian.path %s: cve update downloads the tracker's plain .json; point the path at a .json file", p.Debian))
		} else {
			add("debian", debianURL, p.Debian, load(cve.LoadDebianTracker))
		}
	}

	if p.OVAL != "" {
		if !isDir(p.OVAL) {
			errs = append(errs, fmt.Errorf("cve.oval.path %s: cve update needs a directory, one file per release", p.OVAL))
		} else {
			releases := slices.Clone(w.OVAL)
			// Copies on disk under another name than cve update's own (an
			// uncompressed .xml): replaced once the release's file is in,
			// or the loader would read the release twice.
			others := map[string][]string{}
			for _, name := range dirNames(p.OVAL) {
				for product, src := range ovalSources {
					if m := src.file.FindStringSubmatch(name); m != nil {
						key := product + ":" + m[1]
						releases = append(releases, key)
						if name != src.name(m[1]) {
							others[key] = append(others[key], filepath.Join(p.OVAL, name))
						}
					}
				}
			}
			seen := map[string]bool{}
			for _, r := range releases {
				product, rel, err := ParseOVALRelease(r)
				if err != nil {
					errs = append(errs, err)
					continue
				}
				key := product + ":" + rel
				if seen[key] {
					continue
				}
				seen[key] = true
				src := ovalSources[product]
				add("oval", src.url(rel), filepath.Join(p.OVAL, src.name(rel)), load(cve.LoadOVAL))
				items[len(items)-1].replaces = others[key]
			}
		}
	}

	if p.Alpine != "" {
		if !isDir(p.Alpine) {
			errs = append(errs, fmt.Errorf("cve.alpine.path %s: cve update needs a directory, two files per branch", p.Alpine))
		} else {
			branches := slices.Clone(w.Alpine)
			for _, name := range dirNames(p.Alpine) {
				if m := alpineFile.FindStringSubmatch(name); m != nil {
					branches = append(branches, m[1])
				}
			}
			for _, b := range dedupe(branches) {
				if !alpineBranch.MatchString(b) {
					errs = append(errs, fmt.Errorf("alpine branch %q: want vMAJOR.MINOR, e.g. v3.22", b))
					continue
				}
				for _, repo := range []string{"main", "community"} {
					add("alpine", fmt.Sprintf(alpineURL, b, repo), filepath.Join(p.Alpine, b+"-"+repo+".json"), load(cve.LoadAlpineSecdb))
				}
			}
		}
	}

	if p.MariaDB != "" {
		add("mariadb", mariadbURL, p.MariaDB, load(cve.LoadMariaDB))
	}
	if p.Atlassian != "" {
		add("atlassian", atlassianURL, p.Atlassian, load(cve.LoadAtlassian))
	}

	if p.PostgreSQL != "" {
		if !isDir(p.PostgreSQL) {
			add("postgresql", pgURL, p.PostgreSQL, load(cve.LoadPostgreSQL))
		} else {
			add("postgresql", pgURL, filepath.Join(p.PostgreSQL, pgMainName), load(cve.LoadPostgreSQL))
			majors := slices.Clone(w.PostgreSQL)
			for _, name := range dirNames(p.PostgreSQL) {
				if m := pgFile.FindStringSubmatch(name); m != nil {
					majors = append(majors, m[1])
				}
			}
			for _, m := range dedupe(majors) {
				if !pgMajor.MatchString(m) {
					errs = append(errs, fmt.Errorf("postgresql major %q: want e.g. 13 or 9.6", m))
					continue
				}
				add("postgresql", pgURL+m+"/", filepath.Join(p.PostgreSQL, m+".html"), load(cve.LoadPostgreSQL))
			}
		}
	}

	if p.Nginx != "" {
		add("nginx", nginxURL, p.Nginx, load(cve.LoadNginx))
	}
	return items, errs
}

// ParseOVALRelease splits "ubuntu:noble" into a product with an OVAL
// source and its release, resolving aliases ("rocky-linux:9" is rhel's).
func ParseOVALRelease(s string) (product, release string, err error) {
	product, release, ok := strings.Cut(strings.TrimSpace(s), ":")
	if a, isAlias := ovalAliases[product]; isAlias {
		product = a
	}
	src, known := ovalSources[product]
	switch {
	case !ok || !known:
		return "", "", fmt.Errorf("oval release %q: want ubuntu:<codename>, rhel:<N> (also for Rocky), almalinux:<N>, oracle-linux:<N>, astra-linux:<1.7|1.8> or redos:<7.3|8.0>", s)
	case !src.release.MatchString(release):
		return "", "", fmt.Errorf("oval release %q: %q isn't a %s release", s, release, product)
	}
	return product, release, nil
}

// Dirs lists the configured paths cve update treats as directories. They
// are created even when nothing is planned for them (no OVAL release or
// Alpine branch known yet): the CVE lookup refuses a configured path that
// doesn't exist, so an empty directory keeps check working.
func (p Paths) Dirs() []string {
	var dirs []string
	for _, d := range []string{p.NVD, p.OVAL, p.Alpine, p.PostgreSQL} {
		if d != "" && isDir(d) {
			dirs = append(dirs, d)
		}
	}
	return dirs
}

// isDir reports whether p is a directory, or would be one: a path that
// doesn't exist yet and has no file extension.
func isDir(p string) bool {
	if st, err := os.Stat(p); err == nil {
		return st.IsDir()
	}
	return filepath.Ext(p) == ""
}

func exists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Size() > 0
}

func dirNames(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

func dedupe(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return slices.Compact(out)
}

// postgresMajor is the major of a PostgreSQL version: "17" of "17.2",
// "9.6" of "9.6.24".
func postgresMajor(v string) (string, bool) {
	parts := strings.Split(v, ".")
	n, err := strconv.Atoi(parts[0])
	switch {
	case err != nil:
		return "", false
	case n >= 10:
		return parts[0], true
	case len(parts) >= 2:
		return parts[0] + "." + parts[1], true
	}
	return "", false
}
