# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Alternate runtime image built on the user's own house base
# (ghcr.io/epicmorg/debian:trixie-light) instead of the scratch-based one
# at the repo root (see ../../Dockerfile, used by .goreleaser.yaml's
# dockers_v2 for ghcr.io/epicmorg/enodia). That one copies a raw
# cross-compiled binary in; this one installs the released .deb through
# apt instead — a full Debian userland (glibc, apt, a shell) rather than
# scratch, on purpose, for whatever the house image already brings.
#
# No repo source is needed to build this: everything is fetched over the
# network, so `docker build -f build/docker/Dockerfile build/docker`
# works from an otherwise-empty context.
#
# Release tags are MAJOR.MINOR.PATCH+BUILD, not four dots — confirmed live
# that goreleaser hard-fails on a literal "1.0.0.0" tag (see release.yml's
# own header comment and docs/DECISIONS.md D17's addendum); the real tag
# for a "1.0.0.0"-shaped release is "1.0.0+0".
FROM ghcr.io/epicmorg/debian:trixie-light

# "latest" resolves through GitHub's own /releases/latest/download/ alias,
# which needs no version string at all; pass an exact tag (e.g. "1.0.0+0")
# to pin one instead. TARGETARCH is set automatically by buildx and
# already matches nfpm's own file_name_template exactly ("amd64"/"arm64"),
# no translation needed.
ARG ENODIA_VERSION=1.0.0+0
ARG TARGETARCH=amd64

RUN set -eux; \
	if [ "${ENODIA_VERSION}" = "latest" ]; then \
		url="https://github.com/EpicMorg/enodia/releases/latest/download/enodia_linux_${TARGETARCH}.deb"; \
	else \
		url="https://github.com/EpicMorg/enodia/releases/download/${ENODIA_VERSION}/enodia_linux_${TARGETARCH}.deb"; \
	fi && \
	aria2c \
        --conf-path="/usr/local/share/epicmorg/aria2/config/aria2.conf" \
        --user-agent="$(shuf -n 1 /usr/local/share/epicmorg/user-agents/user-agents.txt)" \
        -d / \
        -o /tmp/enodia.deb \
        "$url" && \
	apt-get update && \
	apt-get install -y --no-install-recommends /tmp/enodia.deb && \
    echo "clean up" && \
    apt-get clean -y && \
    apt-get autoclean -y && \
    rm -rfv /var/lib/apt/lists/* && \
    rm -rfv /var/cache/apt/archives/*.deb && \
    rm -rfv /tmp/*

# Config — enodia.yaml/settings.yaml/credentials.yaml. The .deb itself
# creates this directory empty (see .goreleaser.yaml's nfpms.contents); the
# volume just makes sure it survives container recreation and is easy to
# bind-mount from the host, the same shape as the root Dockerfile's own
# -v /etc/enodia:/config:ro example in README.md.
VOLUME ["/etc/enodia"]

# Working directory for exported reports (inventory.jsonl, HTML exports,
# the resolver's on-disk cache, etc.) — this image's own concern, not
# something the package creates.
RUN mkdir -p /opt/enodia
VOLUME ["/opt/enodia"]
WORKDIR /opt/enodia

RUN /usr/bin/enodia about

ENTRYPOINT ["/usr/bin/enodia"]
