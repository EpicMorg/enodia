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

func loadOSReleaseFixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return string(raw)
}

// osReleaseFamilyTestCase drives one real fixture through the shared probe
// and its own SSH server, exactly as collection would.
type osReleaseFamilyTestCase struct {
	fixture string
	probe   osReleaseFamilyProbe
	version string
}

func runOSReleaseFamilyTest(t *testing.T, tc osReleaseFamilyTestCase) {
	t.Helper()
	fixture := loadOSReleaseFixture(t, tc.fixture)
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		"cat /etc/os-release": fixture,
	})

	target := Target{
		ID: "x", Product: tc.probe.Meta().Product, Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	obs, err := tc.probe.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != tc.version {
		t.Fatalf("got version %q, want %q", obs.Version, tc.version)
	}
	if obs.Extra["hostKeyVerified"] != "true" {
		t.Fatalf("got Extra %+v, want hostKeyVerified=true", obs.Extra)
	}
}

func TestOSReleaseFamilyRealFixtures(t *testing.T) {
	cases := map[string]osReleaseFamilyTestCase{
		"debian":        {"debian_12.txt", osReleaseFamilyProbe{product: "debian", match: osReleaseIDEquals("debian")}, "12"},
		"ubuntu":        {"ubuntu_24.04.txt", osReleaseFamilyProbe{product: "ubuntu", match: osReleaseIDEquals("ubuntu")}, "24.04"},
		"fedora":        {"fedora_44.txt", osReleaseFamilyProbe{product: "fedora", match: osReleaseIDEquals("fedora")}, "44"},
		"rhel":          {"rhel_9.8.txt", osReleaseFamilyProbe{product: "rhel", match: osReleaseIDEquals("rhel")}, "9.8"},
		"rocky-linux":   {"rocky-linux_9.3.txt", osReleaseFamilyProbe{product: "rocky-linux", match: osReleaseIDEquals("rocky")}, "9.3"},
		"almalinux":     {"almalinux_9.8.txt", osReleaseFamilyProbe{product: "almalinux", match: osReleaseIDEquals("almalinux")}, "9.8"},
		"oracle-linux":  {"oracle-linux_9.8.txt", osReleaseFamilyProbe{product: "oracle-linux", match: osReleaseIDEquals("ol")}, "9.8"},
		"amazon-linux":  {"amazon-linux_2023.txt", osReleaseFamilyProbe{product: "amazon-linux", match: osReleaseIDEquals("amzn")}, "2023"},
		"alpine-linux":  {"alpine-linux_3.24.1.txt", osReleaseFamilyProbe{product: "alpine-linux", match: osReleaseIDEquals("alpine")}, "3.24.1"},
		"slackware":     {"slackware_14.2.txt", osReleaseFamilyProbe{product: "slackware", match: osReleaseIDEquals("slackware")}, "14.2"},
		"centos-stream": {"centos-stream_9.txt", osReleaseFamilyProbe{product: "centos-stream", match: func(f map[string]string) bool { return f["ID"] == "centos" && f["NAME"] == "CentOS Stream" }}, "9"},
		"opensuse":      {"opensuse_16.0.txt", osReleaseFamilyProbe{product: "opensuse", match: func(f map[string]string) bool { return len(f["ID"]) >= 8 && f["ID"][:8] == "opensuse" }}, "16.0"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) { runOSReleaseFamilyTest(t, tc) })
	}
}

// The whole point of D9 (product declared explicitly, probe verifies): a
// Rocky Linux box configured under product: almalinux must fail loudly, not
// silently record the wrong distro's identity.
func TestOSReleaseFamilyWrongProductIsErrNotSupported(t *testing.T) {
	fixture := loadOSReleaseFixture(t, "rocky-linux_9.3.txt")
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		"cat /etc/os-release": fixture,
	})

	almalinux := osReleaseFamilyProbe{product: "almalinux", match: osReleaseIDEquals("almalinux")}
	target := Target{
		ID: "x", Product: "almalinux", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	_, err := almalinux.Probe(context.Background(), target)
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

// A host with no /etc/os-release at all (not a systemd-based Linux) fails
// the same way: ErrNotSupported, not a parse error or a hang.
func TestOSReleaseFamilyMissingFileIsErrNotSupported(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, nil) // no "cat /etc/os-release" entry -> exit 1

	debian := osReleaseFamilyProbe{product: "debian", match: osReleaseIDEquals("debian")}
	target := Target{
		ID: "x", Product: "debian", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	_, err := debian.Probe(context.Background(), target)
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestOSReleaseFamilyMeta(t *testing.T) {
	m := osReleaseFamilyProbe{product: "debian", summary: "Debian", resolver: ResolverRef{Type: "endoflife", ID: "debian"}}.Meta()
	if m.Product != "debian" {
		t.Fatalf("got product %q", m.Product)
	}
	if !m.Auth.Required {
		t.Fatal("ssh-based probes cannot work without credentials")
	}
	if !m.Auth.Accepts(AuthPassword) || !m.Auth.Accepts(AuthSSHKey) {
		t.Fatalf("got Auth %+v, want both password and ssh-key accepted", m.Auth)
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "debian" {
		t.Fatalf("got resolver %+v", m.DefaultResolver)
	}
	if m.DefaultScheme != "" {
		t.Fatalf("got DefaultScheme %q, want empty (SSH has no URL scheme, D10)", m.DefaultScheme)
	}
}

func TestParseOSRelease(t *testing.T) {
	fields := parseOSRelease("NAME=\"Debian GNU/Linux\"\nID=debian\nVERSION_ID=\"12\"\n\n# a comment\nEMPTY=\n")
	if fields["NAME"] != "Debian GNU/Linux" {
		t.Fatalf("got NAME %q", fields["NAME"])
	}
	if fields["ID"] != "debian" {
		t.Fatalf("got ID %q", fields["ID"])
	}
	if fields["VERSION_ID"] != "12" {
		t.Fatalf("got VERSION_ID %q", fields["VERSION_ID"])
	}
	if fields["EMPTY"] != "" {
		t.Fatalf("got EMPTY %q", fields["EMPTY"])
	}
}
