// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

import (
	"compress/bzip2"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ovalFix is one "package NAME older than FIXED is affected" fact from one
// OVAL patch definition, with the conditions it was found under.
type ovalFix struct {
	Package string
	Fixed   string
	// Module is the "name:stream" of an RHEL-family AppStream module the
	// fix only applies to ("nodejs:20"), empty when it isn't modular.
	Module string
	// Arch restricts the fix to one host architecture (Oracle Linux
	// publishes x86_64 and aarch64 branches separately), empty when any.
	Arch string
	// Variant is set for Oracle's rebuilt package variants, "ksplice" or
	// "fips": the fix only applies to a package whose installed release
	// carries that marker ("…el9_7_fips", "…ksplice1.el9"), and those
	// packages only to it.
	Variant string
	adv     *ovalAdvisory
}

// ovalKernelFix is Ubuntu's running-kernel check: a kernel flavour whose
// `uname -r` matches Pattern ("6.8.0-\d+(-generic|-generic-64k)") is
// affected while its version is older than Fixed.
type ovalKernelFix struct {
	Flavour string
	Pattern *regexp.Regexp
	Fixed   string
	adv     *ovalAdvisory
}

// ovalAdvisory is one patch definition's metadata: the vendor's own
// advisory (USN-6663-3, RHSA-2024:1234, ALSA-, ELSA-, RLSA-), its page,
// its CVEs and its severity word.
type ovalAdvisory struct {
	ID       string
	URL      string
	CVEs     []string
	Severity string
}

// ovalRelease is every fix one OVAL file publishes for one release.
type ovalRelease struct {
	fixes   map[string][]ovalFix
	kernels []ovalKernelFix
}

// ovalReleaseKey is how an observation finds its release's OVAL file:
// "<probe product>:<release>", release being the Ubuntu codename or the
// RHEL-family major version ("ubuntu:noble", "rhel:9", "almalinux:9",
// "oracle-linux:9").
func ovalReleaseKey(product, release string) string { return product + ":" + release }

// ovalPlatforms maps the platform names RHEL-family OVAL files carry in
// each definition's <affected><platform> — confirmed against each
// vendor's real file — onto this project's probe product ids.
var ovalPlatforms = []struct{ prefix, product string }{
	{"Red Hat Enterprise Linux ", "rhel"},
	{"AlmaLinux ", "almalinux"},
	{"Oracle Linux ", "oracle-linux"},
	{"Rocky Linux ", "rocky-linux"},
}

var (
	reUbuntuDefID = regexp.MustCompile(`^oval:com\.ubuntu\.([a-z]+):`)
	reModule      = regexp.MustCompile(`^Module (\S+) is enabled$`)
	reArch        = regexp.MustCompile(`arch is (\S+)$`)
	reKernelFlav  = regexp.MustCompile(`kernel '([^']+)'`)
	reELTag       = regexp.MustCompile(`\.el(\d+)`)
	reInstalled   = regexp.MustCompile(`^(.+ \d+) is installed$`)
)

// LoadOVAL reads one OVAL file, or every OVAL file directly inside a
// directory, as published by Canonical (com.ubuntu.<codename>.usn.oval.xml),
// Red Hat (rhel-<N>.oval.xml, OVAL v2 — also what Rocky Linux hosts are
// matched against), AlmaLinux (org.almalinux.alsa-<N>.xml) and Oracle
// (com.oracle.elsa-ol<N>.xml). Rocky's own org.rockylinux.rlsa-<N>.xml is
// rejected, see loadOVALFile.
// Each may be plain .xml or the vendor's own .xml.bz2. Which release a
// file is for comes from its content, never its name. See
// docs/DECISIONS.md D43 for what is read and what is deliberately not.
func LoadOVAL(path string) (*Index, error) {
	return loadOVALWith(path, loadOVALFile)
}

func loadOVALWith(path string, loadFile func(string) (string, *ovalRelease, error)) (*Index, error) {
	files, err := resolveOVALFiles(path)
	if err != nil {
		return nil, err
	}
	idx := &Index{byProduct: map[string][]Finding{}, oval: map[string]*ovalRelease{}}
	for _, f := range files {
		key, rel, err := loadFile(f)
		if err != nil {
			return nil, err
		}
		if prev, ok := idx.oval[key]; ok {
			for p, fx := range rel.fixes {
				prev.fixes[p] = append(prev.fixes[p], fx...)
			}
			prev.kernels = append(prev.kernels, rel.kernels...)
			continue
		}
		idx.oval[key] = rel
	}
	return idx, nil
}

func resolveOVALFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		name := strings.ToLower(e.Name())
		if !e.IsDir() && (strings.HasSuffix(name, ".xml") || strings.HasSuffix(name, ".xml.bz2")) {
			out = append(out, filepath.Join(path, e.Name()))
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no .xml/.xml.bz2 OVAL files found", path)
	}
	sort.Strings(out)
	return out, nil
}

// xmlNode is any OVAL element, namespace-agnostic: tests, objects, states
// and variables are spread over four OVAL namespaces (linux-def, red-def,
// ind-def, unix-def) and Oracle writes them unprefixed, so they're matched
// on local name alone.
type xmlNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr `xml:",any,attr"`
	Text     string     `xml:",chardata"`
	Children []xmlNode  `xml:",any"`
}

func (n xmlNode) attr(name string) string {
	for _, a := range n.Attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func (n xmlNode) child(local string) *xmlNode {
	for i := range n.Children {
		if n.Children[i].XMLName.Local == local {
			return &n.Children[i]
		}
	}
	return nil
}

type ovalCriteria struct {
	Criteria  []ovalCriteria  `xml:"criteria"`
	Criterion []ovalCriterion `xml:"criterion"`
}

type ovalCriterion struct {
	TestRef string `xml:"test_ref,attr"`
	Comment string `xml:"comment,attr"`
	Negate  string `xml:"negate,attr"`
}

type ovalDefinition struct {
	ID       string       `xml:"id,attr"`
	Class    string       `xml:"class,attr"`
	Criteria ovalCriteria `xml:"criteria"`
	Metadata struct {
		Title      string   `xml:"title"`
		Platforms  []string `xml:"affected>platform"`
		References []struct {
			Source string `xml:"source,attr"`
			RefID  string `xml:"ref_id,attr"`
			RefURL string `xml:"ref_url,attr"`
		} `xml:"reference"`
		Advisory struct {
			Severity string   `xml:"severity"`
			CVEs     []string `xml:"cve"`
		} `xml:"advisory"`
	} `xml:"metadata"`
}

// ovalTest is a test reduced to what extraction reads.
type ovalTest struct {
	kind   string // local element name: rpminfo_test, dpkginfo_test, uname_test, variable_test, ...
	object string
	state  string
}

// ovalState is a state reduced to its one comparison: the evr (rpminfo,
// dpkginfo), value (variable) or os_release (uname) element.
type ovalState struct {
	op, value, datatype string
}

func openOVAL(path string) (io.Reader, func(), error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	if strings.HasSuffix(strings.ToLower(path), ".bz2") {
		return bzip2.NewReader(f), func() { _ = f.Close() }, nil
	}
	return f, func() { _ = f.Close() }, nil
}

func loadOVALFile(path string) (string, *ovalRelease, error) {
	r, closeFn, err := openOVAL(path)
	if err != nil {
		return "", nil, err
	}
	defer closeFn()

	var (
		defs      []ovalDefinition
		tests     = map[string]ovalTest{}
		objects   = map[string][]string{} // object id -> package names, or a var_ref as "var:<id>"
		states    = map[string]ovalState{}
		variables = map[string][]string{}
	)
	dec := xml.NewDecoder(r)
	var section string
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "definitions", "tests", "objects", "states", "variables":
				section = t.Name.Local
				continue
			}
			switch section {
			case "definitions":
				var d ovalDefinition
				if err := dec.DecodeElement(&d, &t); err != nil {
					return "", nil, fmt.Errorf("parsing %s: %w", path, err)
				}
				if d.Class == "patch" {
					defs = append(defs, d)
				}
			case "tests", "objects", "states", "variables":
				var n xmlNode
				if err := dec.DecodeElement(&n, &t); err != nil {
					return "", nil, fmt.Errorf("parsing %s: %w", path, err)
				}
				indexOVALNode(section, n, tests, objects, states, variables)
			}
		case xml.EndElement:
			if t.Name.Local == section {
				section = ""
			}
		}
	}
	if len(defs) == 0 {
		return "", nil, fmt.Errorf("%s: no OVAL patch definitions — is this a vendor OVAL file?", path)
	}

	product, release, err := ovalFileRelease(defs)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", path, err)
	}
	if product == "rocky-linux" {
		return "", nil, fmt.Errorf("%s: Rocky Linux's own OVAL is not used — measured on a real Rocky 9.3 host it holds 13 of the 130 "+
			"advisories dnf reports, with fixed versions from unrelated later updates; Rocky hosts are matched against "+
			"Red Hat's rhel-%s.oval.xml instead (docs/DECISIONS.md D43), put that one in cve.oval.path", path, release)
	}
	rel := &ovalRelease{fixes: map[string][]ovalFix{}}
	x := ovalExtractor{rel: rel, tests: tests, objects: objects, states: states, variables: variables, release: release, rpmFamily: product != "ubuntu"}
	for i := range defs {
		x.definition(&defs[i])
	}
	if len(rel.fixes) == 0 && len(rel.kernels) == 0 {
		return "", nil, fmt.Errorf("%s: no package version checks found (Ubuntu's oci.* variant, which checks files instead of packages, isn't supported — use com.ubuntu.<codename>.usn.oval.xml)", path)
	}
	return ovalReleaseKey(product, release), rel, nil
}

func indexOVALNode(section string, n xmlNode, tests map[string]ovalTest, objects map[string][]string, states map[string]ovalState, variables map[string][]string) {
	id := n.attr("id")
	switch section {
	case "tests":
		t := ovalTest{kind: n.XMLName.Local}
		if o := n.child("object"); o != nil {
			t.object = o.attr("object_ref")
		}
		if s := n.child("state"); s != nil {
			t.state = s.attr("state_ref")
		}
		tests[id] = t
	case "objects":
		if name := n.child("name"); name != nil {
			if ref := name.attr("var_ref"); ref != "" {
				objects[id] = []string{"var:" + ref}
			} else {
				objects[id] = []string{strings.TrimSpace(name.Text)}
			}
		}
	case "states":
		for _, field := range []string{"evr", "value", "os_release"} {
			if c := n.child(field); c != nil {
				states[id] = ovalState{op: c.attr("operation"), value: strings.TrimSpace(c.Text), datatype: c.attr("datatype")}
				break
			}
		}
	case "variables":
		if n.XMLName.Local == "constant_variable" {
			var vals []string
			for _, c := range n.Children {
				if c.XMLName.Local == "value" {
					vals = append(vals, strings.TrimSpace(c.Text))
				}
			}
			variables[id] = vals
		}
	}
}

// ovalFileRelease works out which release a file is for from its own
// definitions: Ubuntu's definition ids carry the codename
// ("oval:com.ubuntu.noble:def:..."). RHEL-family definitions name their
// platform ("Red Hat Enterprise Linux 9") in <affected><platform> and/or
// in an "AlmaLinux 9 is installed" criterion — AlmaLinux's carry no
// platform element at all, only the criterion (confirmed live). The most
// common one wins: Oracle's and Rocky's files also carry a few
// definitions for neighbouring releases (confirmed live:
// com.oracle.elsa-ol9.xml has 2192 "Oracle Linux 9", 126 "Oracle Linux 8").
func ovalFileRelease(defs []ovalDefinition) (product, release string, err error) {
	if m := reUbuntuDefID.FindStringSubmatch(defs[0].ID); m != nil {
		return "ubuntu", m[1], nil
	}
	count := map[[2]string]int{}
	add := func(platform string) {
		for _, vp := range ovalPlatforms {
			if rest, ok := strings.CutPrefix(platform, vp.prefix); ok {
				count[[2]string{vp.product, strings.TrimSpace(rest)}]++
			}
		}
	}
	var walkInstalled func(c ovalCriteria)
	walkInstalled = func(c ovalCriteria) {
		for _, cr := range c.Criterion {
			if m := reInstalled.FindStringSubmatch(cr.Comment); m != nil {
				add(m[1])
			}
		}
		for _, sub := range c.Criteria {
			walkInstalled(sub)
		}
	}
	for _, d := range defs {
		for _, p := range d.Metadata.Platforms {
			add(p)
		}
		walkInstalled(d.Criteria)
	}
	best := 0
	for k, n := range count {
		if n > best || n == best && k[0]+k[1] < product+release {
			product, release, best = k[0], k[1], n
		}
	}
	if best == 0 {
		return "", "", fmt.Errorf("can't tell which release this OVAL file is for (no Ubuntu id, no known platform)")
	}
	return product, release, nil
}

type ovalExtractor struct {
	rel       *ovalRelease
	tests     map[string]ovalTest
	objects   map[string][]string
	states    map[string]ovalState
	variables map[string][]string
	release   string
	rpmFamily bool
}

type ovalContext struct {
	module, arch, variant string
}

func (x *ovalExtractor) definition(d *ovalDefinition) {
	adv := &ovalAdvisory{Severity: strings.ToLower(d.Metadata.Advisory.Severity)}
	seen := map[string]bool{}
	addCVE := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			adv.CVEs = append(adv.CVEs, id)
		}
	}
	// The vendor's own advisory wins over the RHSA it rebuilds: AlmaLinux
	// cites both, RHSA first (confirmed live).
	for _, ref := range d.Metadata.References {
		switch strings.ToUpper(ref.Source) {
		case "CVE":
			addCVE(ref.RefID)
		default:
			if adv.ID == "" || strings.HasPrefix(adv.ID, "RHSA-") && !strings.HasPrefix(ref.RefID, "RHSA-") {
				adv.ID, adv.URL = ref.RefID, ref.RefURL
			}
		}
	}
	for _, c := range d.Metadata.Advisory.CVEs {
		addCVE(strings.TrimSpace(c))
	}
	if len(adv.CVEs) == 0 {
		return // a bug-fix or enhancement advisory (RHBA, RHEA): nothing to report
	}
	if adv.ID == "" {
		adv.ID = d.Metadata.Title
	}
	x.walk(d.Criteria, ovalContext{}, adv)
}

// walk collects every package check under c. A node's own "Module X is
// enabled", "arch is X", "is ksplice-based" and "is fips patched"
// criteria scope everything else in that node, nested nodes included. Every other test that isn't a
// "package older than" check (the OS-is-installed check, signing keys,
// kpatch state) is not evaluated: the file is already per release, and
// the probe doesn't read signatures — see D43.
func (x *ovalExtractor) walk(c ovalCriteria, ctx ovalContext, adv *ovalAdvisory) {
	var unameTest, varTest *ovalCriterion
	for i, cr := range c.Criterion {
		if m := reModule.FindStringSubmatch(cr.Comment); m != nil {
			ctx.module = m[1]
		}
		if m := reArch.FindStringSubmatch(cr.Comment); m != nil {
			ctx.arch = m[1]
		}
		switch {
		case strings.HasSuffix(cr.Comment, " is ksplice-based"):
			ctx.variant = "ksplice"
		case strings.HasSuffix(cr.Comment, " is fips patched"):
			ctx.variant = "fips"
		}
		switch x.tests[cr.TestRef].kind {
		case "uname_test":
			unameTest = &c.Criterion[i]
		case "variable_test":
			varTest = &c.Criterion[i]
		}
	}
	for _, cr := range c.Criterion {
		if cr.Negate == "true" {
			continue
		}
		t := x.tests[cr.TestRef]
		if t.kind != "rpminfo_test" && t.kind != "dpkginfo_test" {
			continue
		}
		st, ok := x.states[t.state]
		if !ok || st.op != "less than" || st.value == "" {
			continue
		}
		if x.rpmFamily && x.otherELRelease(st.value) {
			continue
		}
		for _, name := range x.objectNames(t.object) {
			x.rel.fixes[name] = append(x.rel.fixes[name], ovalFix{Package: name, Fixed: st.value, Module: ctx.module, Arch: ctx.arch, Variant: ctx.variant, adv: adv})
		}
	}
	if unameTest != nil && varTest != nil && !x.rpmFamily {
		pat, fixed := x.states[x.tests[unameTest.TestRef].state], x.states[x.tests[varTest.TestRef].state]
		if re, err := regexp.Compile("^(?:" + pat.value + ")$"); err == nil && fixed.op == "less than" && fixed.value != "" {
			flavour := "linux"
			if m := reKernelFlav.FindStringSubmatch(unameTest.Comment); m != nil {
				flavour = m[1]
			}
			x.rel.kernels = append(x.rel.kernels, ovalKernelFix{Flavour: flavour, Pattern: re, Fixed: fixed.value, adv: adv})
		}
	}
	for _, sub := range c.Criteria {
		x.walk(sub, ctx, adv)
	}
}

// otherELRelease reports whether an RHEL-family fixed version is tagged
// for a different major release than this file's (".el8" in a release-9
// file). Confirmed live: Oracle's com.oracle.elsa-ol9.xml carries some
// definitions for Oracle Linux 8 and 10 too (and Rocky's rlsa-9 file
// mixes el8 and el9 fixes inside one definition, one reason it's not used).
func (x *ovalExtractor) otherELRelease(fixed string) bool {
	m := reELTag.FindStringSubmatch(fixed)
	if m == nil {
		return false
	}
	major, _, _ := strings.Cut(x.release, ".")
	n, err := strconv.Atoi(m[1])
	return err == nil && strconv.Itoa(n) != major
}

func (x *ovalExtractor) objectNames(objID string) []string {
	names := x.objects[objID]
	if len(names) == 1 {
		if ref, ok := strings.CutPrefix(names[0], "var:"); ok {
			return x.variables[ref]
		}
	}
	return names
}
