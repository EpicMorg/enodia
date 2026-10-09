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

func minioTarget(addr, fp string, options map[string]string) Target {
	return Target{
		ID: "x", Product: "minio", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
		Options: options,
	}
}

// minio_RELEASE_INHOUSE.2025-03-12_version.txt is `minio --version` from a
// real in-house MinIO build running as a systemd service, its builder
// marker and commit-id replaced by placeholders.
func loadMinIOFixture(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "minio_RELEASE_INHOUSE.2025-03-12_version.txt"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return string(raw)
}

func TestMinIOProbeOnHost(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{minioVersionCommand: loadMinIOFixture(t)})
	obs, err := minioProbe{}.Probe(context.Background(), minioTarget(addr, fp, nil))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "RELEASE_INHOUSE.2025-03-12T18-04-18Z" || obs.Extra["build"] != "INHOUSE" ||
		obs.Extra["commit"] != "0123456789abcdef0123456789abcdef01234567" || obs.Extra["runtime"] != "go1.24.4" {
		t.Fatalf("got %q %+v", obs.Version, obs.Extra)
	}
}

func TestMinIOProbeInContainer(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		"podman exec minio sh -c '" + minioVersionCommand + "'": "minio version RELEASE.2025-10-15T17-29-55Z (commit-id=abc123)\nRuntime: go1.24.6 linux/amd64\n",
	})
	obs, err := minioProbe{}.Probe(context.Background(), minioTarget(addr, fp, map[string]string{"container": "minio", "container_runtime": "podman"}))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "RELEASE.2025-10-15T17-29-55Z" || obs.Extra["build"] != "" || obs.Extra["container"] != "minio" {
		t.Fatalf("got %q %+v", obs.Version, obs.Extra)
	}
}

func TestMinIOProbeNotInstalled(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{minioVersionCommand: "sh: 1: minio: not found\n"})
	if _, err := (minioProbe{}).Probe(context.Background(), minioTarget(addr, fp, nil)); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestMinIOProbeMeta(t *testing.T) {
	m := minioProbe{}.Meta()
	if m.Product != "minio" || !m.Auth.Required || !m.Auth.Accepts(AuthSSHKey) || m.DefaultResolver != (ResolverRef{Type: "github", ID: "minio/minio"}) {
		t.Fatalf("got %+v", m)
	}
}
