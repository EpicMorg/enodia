# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The published release image (see .goreleaser.yaml's dockers_v2 block,
# ghcr.io/epicmorg/enodia). goreleaser cross-compiles the binaries for every
# target platform beforehand, so this file only assembles the image — it
# never compiles Go code, which would just redo work goreleaser already did.
#
# Built on the user's own house image (ghcr.io/epicmorg/debian:trixie-light)
# rather than scratch, by request — D15's non-daemon, minimal-surface
# reasoning still holds in general, this is a deliberate one-off preference
# for this project's own published image. Copies the raw cross-compiled
# binary in directly (not the .deb — an earlier version of this file
# installed that via apt; reverted by request) and runs as root (the house
# image's own default), rather than a dedicated non-root user: this is the
# one repo-published image, and both were explicit calls for it
# specifically. build/docker/Dockerfile (a separate, hand-built image,
# unrelated to this one) is where the fixed enodia uid/gid 1337
# (build/nfpm/preinstall.sh) actually matters, since that one installs the
# .deb.
#
# amd64 only (no arm64) — see docs/DECISIONS.md D17's "Revisited" entry.
#
# For the GitHub Action wrapper (action.yml), which needs a shell, see
# action.Dockerfile instead — this one is deliberately shell-less beyond
# what the house image already carries.

FROM ghcr.io/epicmorg/debian:trixie-light

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/enodia /usr/bin/enodia

WORKDIR /opt/enodia

ENTRYPOINT ["/usr/bin/enodia"]
