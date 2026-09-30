// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"testing"
	"time"
)

// <product>_<version>_packages.txt are the probe command's full output,
// captured live inside the matching container image (registry.access.
// redhat.com/ubi9/ubi:9.4, almalinux:9.0-20220901, oraclelinux:9,
// rockylinux:9.3, ubuntu:noble-20240605); uname is the container host's
// own Debian kernel.
func TestOSReleaseFamilyReadsRPMPackages(t *testing.T) {
	for _, tc := range []struct {
		product, id, fixture string
		packages             int
		openssl              string
	}{
		{"rhel", "rhel", "rhel_9.4_packages.txt", 189, "1:3.0.7-28.el9_4"},
		{"almalinux", "almalinux", "almalinux_9.0_packages.txt", 150, "1:3.0.1-41.el9_0"},
		{"oracle-linux", "ol", "oracle-linux_9.8_packages.txt", 186, "1:3.5.5-2.0.1.el9_8"},
		{"rocky-linux", "rocky", "rocky-linux_9.3_packages.txt", 141, "1:3.0.7-24.el9"},
	} {
		t.Run(tc.product, func(t *testing.T) {
			p := osReleaseFamilyProbe{product: tc.product, match: osReleaseIDEquals(tc.id), packages: packagesRPM}
			addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
				"cat /etc/os-release 2>/dev/null" + packagesCommand(packagesRPM): loadOSReleaseFixture(t, tc.fixture),
			})
			obs, err := p.Probe(context.Background(), Target{
				ID: "x", Product: tc.product, Address: addr,
				Creds: Credentials{Username: "probeuser", Password: "probepass"},
				TLS:   TLSSettings{PinSHA256: []string{fp}}, Timeout: 2 * time.Second,
			})
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if len(obs.Packages) != tc.packages {
				t.Errorf("got %d packages, want %d", len(obs.Packages), tc.packages)
			}
			if obs.Packages["openssl-libs"] != tc.openssl {
				t.Errorf("openssl-libs = %q, want %q", obs.Packages["openssl-libs"], tc.openssl)
			}
			if _, ok := obs.Packages["gpg-pubkey"]; ok {
				t.Error("gpg-pubkey is an imported key, not a package")
			}
			if obs.Extra["arch"] != "x86_64" || obs.Extra["kernelRelease"] != "6.12.107+deb13-amd64" {
				t.Errorf("got Extra %v", obs.Extra)
			}
		})
	}
}

func TestUbuntuProbeReadsPackages(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		ubuntuProbeCommand: loadUbuntuFixture(t, "ubuntu_24.04_packages.txt"),
	})
	obs, err := ubuntuProbe{}.Probe(context.Background(), ubuntuTestTarget(addr, fp))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(obs.Packages) != 121 || obs.Packages["libssl3t64"] != "3.0.13-0ubuntu3.1" {
		t.Errorf("got %d packages, libssl3t64 %q", len(obs.Packages), obs.Packages["libssl3t64"])
	}
	if obs.Extra["codename"] != "noble" || obs.Extra["kernelVersion"] == "" {
		t.Errorf("got Extra %v", obs.Extra)
	}
}

// Every RHEL-family registration and Linux Mint collects packages;
// everything else in the family still runs the plain `cat` it always did.
func TestOSReleaseFamilyPackageRegistrations(t *testing.T) {
	want := map[string]packageKind{
		"rhel": packagesRPM, "almalinux": packagesRPM, "oracle-linux": packagesRPM, "rocky-linux": packagesRPM,
		"linuxmint": packagesDpkgBinary, "alpine-linux": packagesAPK, "fedora": packagesNone, "centos-stream": packagesNone,
	}
	for product, kind := range want {
		p, err := Get(product)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.(osReleaseFamilyProbe).packages; got != kind {
			t.Errorf("%s: packages = %v, want %v", product, got, kind)
		}
	}
}

func TestParseRPMPackages(t *testing.T) {
	out := "" +
		"bash\t(none):5.1.8-9.el9\t(none)\n" +
		"gpg-pubkey\t(none):fd431d51-4ae0493b\t(none)\n" +
		"nodejs\t1:18.20.2-1.module+el9.4.0+21731+46b5c8fd\tnodejs:18:9040020240408140937:rhel9\n" +
		// installonly kernels: the running one wins over older and newer
		"kernel-core\t(none):5.14.0-362.8.1.el9_3\t(none)\n" +
		"kernel-core\t(none):5.14.0-427.13.1.el9_4\t(none)\n" +
		"kernel-core\t(none):5.14.0-427.16.1.el9_4\t(none)\n" +
		// multilib: two arches, the oldest wins
		"glibc\t(none):2.34-100.el9_4.2\t(none)\n" +
		"glibc\t(none):2.34-100.el9\t(none)\n" +
		"garbage\n"
	pkgs, modules := parseRPMPackages(out, "5.14.0-427.13.1.el9_4.x86_64", "x86_64")
	want := map[string]string{
		"bash":        "0:5.1.8-9.el9",
		"nodejs":      "1:18.20.2-1.module+el9.4.0+21731+46b5c8fd",
		"kernel-core": "0:5.14.0-427.13.1.el9_4",
		"glibc":       "0:2.34-100.el9",
	}
	if len(pkgs) != len(want) {
		t.Fatalf("got %v, want %v", pkgs, want)
	}
	for k, v := range want {
		if pkgs[k] != v {
			t.Errorf("%s = %q, want %q", k, pkgs[k], v)
		}
	}
	if len(modules) != 1 || modules["nodejs"] != "nodejs:18" {
		t.Errorf("modules = %v", modules)
	}

	// Without a running kernel to prefer, installonly packages fall back
	// to the oldest, like everything else.
	pkgs, _ = parseRPMPackages(out, "", "")
	if pkgs["kernel-core"] != "0:5.14.0-362.8.1.el9_3" {
		t.Errorf("kernel-core = %q", pkgs["kernel-core"])
	}
}

// rpm older than 4.14 has no MODULARITYLABEL tag: the probe's fallback
// query prints two columns, which must parse the same, minus modules.
func TestParseRPMPackagesWithoutModularityLabel(t *testing.T) {
	pkgs, modules := parseRPMPackages("bash\t(none):4.2.46-35.el7_9\nopenssl-libs\t1:1.0.2k-26.el7_9\n", "", "")
	if pkgs["openssl-libs"] != "1:1.0.2k-26.el7_9" || len(pkgs) != 2 || modules != nil {
		t.Fatalf("got %v, %v", pkgs, modules)
	}
}

// alpine-linux_3.20.0_packages.txt is the probe command's output from
// alpine:3.20.0: 14 binary packages from 9 origins (libcrypto3 and
// libssl3 are both openssl's).
func TestOSReleaseFamilyReadsAPKPackages(t *testing.T) {
	p := osReleaseFamilyProbe{product: "alpine-linux", match: osReleaseIDEquals("alpine"), packages: packagesAPK}
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		"cat /etc/os-release 2>/dev/null" + packagesCommand(packagesAPK): loadOSReleaseFixture(t, "alpine-linux_3.20.0_packages.txt"),
	})
	obs, err := p.Probe(context.Background(), Target{
		ID: "x", Product: "alpine-linux", Address: addr,
		Creds: Credentials{Username: "probeuser", Password: "probepass"},
		TLS:   TLSSettings{PinSHA256: []string{fp}}, Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "3.20.0" || len(obs.Packages) != 9 || obs.Packages["openssl"] != "3.3.0-r2" || obs.Packages["musl"] != "1.2.5-r0" {
		t.Fatalf("got version %q, packages %v", obs.Version, obs.Packages)
	}
	if _, ok := obs.Packages["libcrypto3"]; ok {
		t.Error("binary package names must fold into their origin")
	}
}

func TestParseAPKPackages(t *testing.T) {
	got := parseAPKPackages("P:libcrypto3\nV:3.3.0-r3\no:openssl\n" +
		"P:libssl3\nV:3.3.0-r2\no:openssl\n" + // mid-upgrade: the oldest wins
		"P:noorigin\nV:1.0-r0\n")
	if len(got) != 2 || got["openssl"] != "3.3.0-r2" || got["noorigin"] != "1.0-r0" {
		t.Fatalf("got %v", got)
	}
}
