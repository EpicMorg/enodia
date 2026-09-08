# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Used only by action.yml (the GitHub Action wrapper), which needs a shell
# to join its "args" input into argv before exec'ing enodia. The published
# release image (Dockerfile, ghcr.io/epicmorg/enodia) is scratch-based and
# deliberately has none — these are two different jobs, hence two files.
#
# Unlike Dockerfile, this one does compile from source: a GitHub Action
# checkout has no pre-built per-platform binaries lying around the way
# goreleaser's build context does, so there is nothing to reuse here.

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/enodia ./cmd/enodia

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/enodia /usr/local/bin/enodia
ENTRYPOINT ["/usr/local/bin/enodia"]
