// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"fmt"
	"regexp"
)

// Target options for SSH probes whose software may run in a container on
// the SSH host instead of on the host itself (freeradius, minio, kafka).
const (
	// containerOption names the container to run the probe's command in.
	containerOption = "container"
	// containerRuntimeOption is the container CLI: "docker" (default) or
	// "podman".
	containerRuntimeOption = "container_runtime"
)

// containerNamePattern is what Docker itself accepts as a container name
// ([a-zA-Z0-9][a-zA-Z0-9_.-]*) — checked before the name goes into a
// remote shell command.
var containerNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// containerCommand is cmd as is, or wrapped in `<runtime> exec <container>
// sh -c '...'` when t's options.container is set. cmd must not contain a
// single quote.
func containerCommand(t Target, cmd string) (string, error) {
	container := t.Options[containerOption]
	if container == "" {
		return cmd, nil
	}
	if !containerNamePattern.MatchString(container) {
		return "", fmt.Errorf("%w: options.%s %q is not a valid container name", ErrNotSupported, containerOption, container)
	}
	runtime := t.Options[containerRuntimeOption]
	switch runtime {
	case "":
		runtime = "docker"
	case "docker", "podman":
	default:
		return "", fmt.Errorf("%w: options.%s must be docker or podman, not %q", ErrNotSupported, containerRuntimeOption, runtime)
	}
	return runtime + " exec " + container + " sh -c '" + cmd + "'", nil
}
