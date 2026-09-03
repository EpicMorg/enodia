#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Installs the enodia binary for the current OS/arch from GitHub Releases.
#
#   curl -sSL https://raw.githubusercontent.com/EpicMorg/enodia/master/install.sh | sh
#
# docs/ROADMAP.md: "Install script served from a path, never the site root,
# and never User-Agent-dependent." raw.githubusercontent.com already
# satisfies both for free — it serves this exact file from a path under the
# repo, identically to every client, with no server-side logic of its own.
# Everything OS/arch-specific is decided in here (via uname), not by the
# server.
#
# Env vars:
#   ENODIA_VERSION    version tag to install, e.g. "v1.2.3" (default: latest)
#   ENODIA_INSTALL_DIR  directory to install into (default: /usr/local/bin)

set -eu

repo="EpicMorg/enodia"
install_dir="${ENODIA_INSTALL_DIR:-/usr/local/bin}"

os=$(uname -s)
case "$os" in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	*)
		echo "install.sh: unsupported OS: $os (only linux and darwin are supported; see releases for Windows binaries)" >&2
		exit 1
		;;
esac

arch=$(uname -m)
case "$arch" in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*)
		echo "install.sh: unsupported architecture: $arch" >&2
		exit 1
		;;
esac

version="${ENODIA_VERSION:-}"
if [ -z "$version" ]; then
	version=$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" |
		grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
	if [ -z "$version" ]; then
		echo "install.sh: could not determine the latest release; set ENODIA_VERSION to install a specific one" >&2
		exit 1
	fi
fi

# Must match archives.name_template in .goreleaser.yaml exactly.
archive="enodia_${os}_${arch}.tar.gz"
base_url="https://github.com/${repo}/releases/download/${version}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "install.sh: downloading enodia ${version} for ${os}/${arch}..."
curl -fsSL -o "$tmp/$archive" "$base_url/$archive"
curl -fsSL -o "$tmp/checksums.txt" "$base_url/checksums.txt"

echo "install.sh: verifying checksum..."
(cd "$tmp" && grep " $archive\$" checksums.txt | sha256sum -c -)

tar -xzf "$tmp/$archive" -C "$tmp" enodia

if [ -w "$install_dir" ]; then
	install -m 0755 "$tmp/enodia" "$install_dir/enodia"
else
	echo "install.sh: $install_dir is not writable, retrying with sudo..."
	sudo install -m 0755 "$tmp/enodia" "$install_dir/enodia"
fi

echo "install.sh: installed $("$install_dir/enodia" version) to $install_dir/enodia"
