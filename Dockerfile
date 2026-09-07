# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The published release image (see .goreleaser.yaml's dockers_v2 block,
# ghcr.io/epicmorg/enodia). goreleaser cross-compiles the binaries for every
# target platform beforehand, so this file only assembles the image — it
# never compiles Go code, which would just redo work goreleaser already did
# and defeat cross-compilation.
#
# D15: scratch, non-root, no daemon — docker run --rm ... check ... is the
# whole interface. D1: a static Go binary needs nothing else at runtime
# except a CA bundle, since scratch has none of its own — without it every
# TLS call fails with an unhelpful error.
#
# For the GitHub Action wrapper (action.yml), which needs a shell, see
# action.Dockerfile instead — this one is deliberately shell-less.

FROM alpine:3.20 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch
ARG TARGETPLATFORM
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY $TARGETPLATFORM/enodia /usr/bin/enodia

# The conventional "nobody" UID/GID: scratch has no /etc/passwd to resolve a
# named user against, so it must be numeric.
USER 65532:65532

ENTRYPOINT ["/usr/bin/enodia"]
