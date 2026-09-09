# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The published release image (see .goreleaser.yaml's dockers_v2 block,
# ghcr.io/epicmorg/enodia). Built on the user's own house image
# (ghcr.io/epicmorg/debian:trixie-light) rather than scratch: installs the
# .deb goreleaser's nfpm step just built (passed into the build context via
# dockers_v2.extra_files, since nfpm runs before docker in goreleaser's own
# pipeline order) through apt — the same install path build/docker/
# Dockerfile already uses for hand-built images. Reusing it here rather
# than diverging (e.g. copying the raw binary in) matters concretely:
# build/nfpm/preinstall.sh fixes the enodia user at uid/gid 1337
# specifically so bind-mounted /etc/enodia, /opt/enodia, /var/enodia line
# up across every image this project ships — a raw-binary Dockerfile would
# need to reimplement that user/permission setup by hand and could drift
# from it.
#
# amd64 only (no arm64) — see docs/DECISIONS.md D17's "Revisited" entry.
#
# For the GitHub Action wrapper (action.yml), which needs a shell, see
# action.Dockerfile instead — unrelated to this file.

FROM ghcr.io/epicmorg/debian:trixie-light

COPY dist/enodia_linux_amd64.deb /tmp/enodia.deb
RUN apt-get update && \
    apt-get install -y --no-install-recommends /tmp/enodia.deb && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/enodia.deb

USER enodia
WORKDIR /opt/enodia

ENTRYPOINT ["/usr/bin/enodia"]
