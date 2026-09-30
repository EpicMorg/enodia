// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func loadDebianFixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return string(raw)
}

const debianProbeCmd = debianProbeCommand

func debianTestTarget(addr, fp string) Target {
	return Target{
		ID: "x", Product: "debian", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}
}

// debian_12.15.txt and debian_13.6.txt are real, live-captured os-release +
// debian_version pairs (docker.io/debian:bookworm and :trixie) — confirmed
// that VERSION_ID alone ("12", "13") never carries the point release, only
// /etc/debian_version does.
func TestDebianProbeParsesRealFixtures(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		version string
	}{
		{"debian_12.15.txt", "12.15"},
		{"debian_13.6.txt", "13.6"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
				debianProbeCmd: loadDebianFixture(t, tc.fixture),
			})

			p := debianProbe{}
			obs, err := p.Probe(context.Background(), debianTestTarget(addr, fp))
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if obs.Version != tc.version {
				t.Fatalf("got version %q, want %q", obs.Version, tc.version)
			}
			if obs.Extra["debianVersion"] != tc.version {
				t.Fatalf("got Extra %+v, want debianVersion=%q", obs.Extra, tc.version)
			}
			if obs.Extra["hostKeyVerified"] != "true" {
				t.Fatalf("got Extra %+v, want hostKeyVerified=true", obs.Extra)
			}
		})
	}
}

// A real Ubuntu 24.04 image was confirmed live to carry its own
// /etc/debian_version, inherited from its build lineage, reading
// "trixie/sid" — meaningless for Ubuntu's own version. This must never be
// mistaken for a Debian instance just because that file happens to exist.
func TestDebianProbeRejectsUbuntusInheritedDebianVersionFile(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		debianProbeCmd: loadDebianFixture(t, "ubuntu_2404_debian_version_trap.txt"),
	})

	p := debianProbe{}
	_, err := p.Probe(context.Background(), debianTestTarget(addr, fp))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

// A real debian:testing image has no VERSION_ID in os-release at all (no
// numbered release exists yet) and its own /etc/debian_version reads
// "forky/sid", which debianVersionPattern correctly does not treat as a
// point release. Since neither source has a usable version, this must
// report ErrUnparseable rather than inventing one — same as
// osReleaseFamilyProbe already does for a missing VERSION_ID.
func TestDebianProbeTestingHasNoUsableVersion(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		debianProbeCmd: loadDebianFixture(t, "debian_testing_forky-sid.txt"),
	})

	p := debianProbe{}
	_, err := p.Probe(context.Background(), debianTestTarget(addr, fp))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

// If /etc/debian_version were ever missing entirely on a real Debian box,
// falling back to VERSION_ID's bare major is still strictly better than
// failing the whole probe over one optional file.
func TestDebianProbeMissingDebianVersionFallsBackToVersionID(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		debianProbeCmd: "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n===ENODIA-DEBIAN-VERSION===\n",
	})

	p := debianProbe{}
	obs, err := p.Probe(context.Background(), debianTestTarget(addr, fp))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "12" {
		t.Fatalf("got version %q, want 12 (VERSION_ID fallback)", obs.Version)
	}
	if _, ok := obs.Extra["debianVersion"]; ok {
		t.Fatalf("got Extra %+v, want no debianVersion key when the file was empty", obs.Extra)
	}
}

func TestDebianProbeMeta(t *testing.T) {
	m := debianProbe{}.Meta()
	if m.Product != "debian" {
		t.Fatalf("got product %q", m.Product)
	}
	if !m.Auth.Required {
		t.Fatal("ssh-based probes cannot work without credentials")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "debian" {
		t.Fatalf("got resolver %+v", m.DefaultResolver)
	}
}

// debian_{bookworm,trixie}_packages.txt are debianProbeCommand's full
// output captured live from docker.io/library/debian:bookworm and :trixie
// (uname -v is the container host's own Debian kernel). The older
// fixtures above stop after /etc/debian_version — what a host without
// uname or dpkg-query would give — and must still parse, just with no
// packages.
func TestDebianProbeReadsPackagesAndKernel(t *testing.T) {
	for _, tc := range []struct {
		fixture, codename string
		sources           int // distinct source packages behind the image's ~90 binary ones
		wantPkgs          map[string]string
	}{
		{"debian_bookworm_packages.txt", "bookworm", 63, map[string]string{"bash": "5.2.15-2", "apt": "2.6.1"}},
		{"debian_trixie_packages.txt", "trixie", 55, map[string]string{"bash": "5.2.37-2", "util-linux": "2.41.5-0+deb13u1"}},
	} {
		t.Run(tc.codename, func(t *testing.T) {
			addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
				debianProbeCmd: loadDebianFixture(t, tc.fixture),
			})
			obs, err := debianProbe{}.Probe(context.Background(), debianTestTarget(addr, fp))
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if obs.Extra["codename"] != tc.codename {
				t.Errorf("codename = %q, want %q", obs.Extra["codename"], tc.codename)
			}
			if obs.Extra["kernel"] != "6.12.107-1" {
				t.Errorf("kernel = %q, want 6.12.107-1", obs.Extra["kernel"])
			}
			if len(obs.Packages) != tc.sources {
				t.Errorf("got %d source packages, want %d", len(obs.Packages), tc.sources)
			}
			for name, want := range tc.wantPkgs {
				if got := obs.Packages[name]; got != want {
					t.Errorf("Packages[%q] = %q, want %q", name, got, want)
				}
			}
		})
	}
}

func TestDebianProbeOldFixtureHasNoPackages(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		debianProbeCmd: loadDebianFixture(t, "debian_13.6.txt"),
	})
	obs, err := debianProbe{}.Probe(context.Background(), debianTestTarget(addr, fp))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "13.6" || obs.Packages != nil || obs.Extra["kernel"] != "" {
		t.Fatalf("got version %q, packages %v, kernel %q", obs.Version, obs.Packages, obs.Extra["kernel"])
	}
}

func TestParseDpkgSourcePackages(t *testing.T) {
	got := parseDpkgSourcePackages("" +
		"ii \tacl\t2.3.2-2\n" +
		"rc \tfoo\t1.0-1\n" + // removed, config files left: not installed
		"ii \tlinux\t6.12.111-1\n" +
		"ii \tlinux\t6.12.74-2\n" + // old headers still installed: the oldest wins
		"hi \theld\t2.0\n" + // on hold, still installed
		"iU \tunpacked\t3.0\n" + // unpacked, not configured
		"garbage line\n")
	want := map[string]string{"acl": "2.3.2-2", "linux": "6.12.74-2", "held": "2.0"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if parseDpkgSourcePackages("") != nil {
		t.Fatal("empty output must give nil")
	}
}
