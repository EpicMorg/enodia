// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// minioVersionCommand runs the server binary's own --version, by name and
// then by the path MinIO's packages and docs install it at; `|| true`
// keeps a host without it from failing the command, which is reported from
// the missing version line instead.
const minioVersionCommand = "minio --version 2>&1 || /usr/local/bin/minio --version 2>&1 || true"

// minioVersionPattern reads `minio --version`'s first line, confirmed on
// a real in-house build: "minio version RELEASE_INHOUSE.2025-03-12T18-04-18Z
// (commit-id=0123456789abcdef0123456789abcdef01234567)"; upstream builds
// say RELEASE.<timestamp>. version.Clean folds either into a comparable
// "2025.03.12.18.04.18".
var (
	minioVersionPattern = regexp.MustCompile(`minio version (RELEASE(?:_([A-Za-z0-9]+))?\.\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z)(?: \(commit-id=([0-9a-f]+)\))?`)
	minioRuntimePattern = regexp.MustCompile(`(?m)^Runtime: (go\S+)`)
)

// minioProbe runs `minio --version` over SSH, like freeradius (D45).
//
// MinIO's network surfaces don't give the version without credentials:
// the S3 API's Server header is a bare "MinIO", the Console's anonymous
// API (/api/v1/login) has none, and the admin and Prometheus endpoints need
// an admin key or a generated bearer token. On the fleet this was built
// against, the S3 port wasn't reachable from the network at all, while the
// hosts were already SSH targets. options.container runs the command in a
// Docker/Podman container on the SSH host, as for freeradius.
type minioProbe struct{}

func (minioProbe) Meta() Meta {
	return Meta{
		Product: "minio",
		Summary: "MinIO (server binary, over SSH)",
		Auth:    AuthSpec{Required: true, Kinds: []AuthKind{AuthPassword, AuthSSHKey}},
		// No endoflife.date page (404). minio/minio's release tags are the
		// RELEASE.<timestamp> names the binary reports.
		DefaultResolver: ResolverRef{Type: "github", ID: "minio/minio"},
	}
}

func (minioProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	cmd, err := containerCommand(t, minioVersionCommand)
	if err != nil {
		return obs, err
	}
	out, verified, err := sshRunCommand(ctx, t, cmd)
	if err != nil {
		if isSSHExitError(err) {
			return obs, fmt.Errorf("%w: %w", ErrNotSupported, err)
		}
		return obs, err
	}

	m := minioVersionPattern.FindStringSubmatch(out)
	if m == nil {
		return obs, fmt.Errorf("%w: no MinIO release in the output of minio --version (not installed here, or in a container — see options.%s)",
			ErrNotSupported, containerOption)
	}
	obs.Version = m[1]
	obs.Endpoint = "minio --version"
	obs.Extra = map[string]string{"hostKeyVerified": strconv.FormatBool(verified)}
	if m[2] != "" {
		obs.Extra["build"] = m[2]
	}
	if m[3] != "" {
		obs.Extra["commit"] = m[3]
	}
	if rm := minioRuntimePattern.FindStringSubmatch(out); rm != nil {
		obs.Extra["runtime"] = rm[1]
	}
	if c := t.Options[containerOption]; c != "" {
		obs.Extra["container"] = c
	}
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}
