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
#   ENODIA_VERSION    version tag to install, e.g. "1.2.3+4" (default: latest)
#   ENODIA_INSTALL_DIR  directory to install into (default: /usr/local/bin)
#
# If install_dir isn't writable and sudo doesn't actually work (missing,
# or present but unusable — Termux's own optional `sudo` package exists on
# PATH but just prints "No superuser binary detected" on an unrooted
# device), but $PREFIX is set and its bin/ is writable (Termux and similar
# userland-prefix environments), that's used instead — no separate script
# or name-based "is this Termux" check, just the same curl|sh one-liner
# working there too.

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

version="${ENODIA_VERSION:-latest}"

# Must match archives.name_template in .goreleaser.yaml exactly.
archive="enodia_${os}_${arch}.tar.gz"
if [ "$version" = "latest" ]; then
	# GitHub's own alias — resolves server-side with no API call, so
	# there's no tag_name to parse and no API rate limit to hit (unlike
	# querying https://api.github.com/repos/.../releases/latest first).
	base_url="https://github.com/${repo}/releases/latest/download"
else
	base_url="https://github.com/${repo}/releases/download/${version}"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "install.sh: downloading enodia ${version} for ${os}/${arch}..."
curl -fsSL -o "$tmp/$archive" "$base_url/$archive"
curl -fsSL -o "$tmp/checksums.txt" "$base_url/checksums.txt"

echo "install.sh: verifying checksum..."
(cd "$tmp" && grep " $archive\$" checksums.txt | sha256sum -c -)

tar -xzf "$tmp/$archive" -C "$tmp" enodia

installed=0
if [ -w "$install_dir" ]; then
	install -m 0755 "$tmp/enodia" "$install_dir/enodia"
	installed=1
elif command -v sudo >/dev/null 2>&1; then
	echo "install.sh: $install_dir is not writable, retrying with sudo..."
	# A present `sudo` binary isn't proof it actually works — Termux's own
	# optional `sudo` package exists on PATH but fails outright ("No
	# superuser binary detected") on a device with no `su` to escalate to.
	# Only treat this as done if it actually exits 0; otherwise fall
	# through to the $PREFIX check below instead of hard-failing here.
	if sudo install -m 0755 "$tmp/enodia" "$install_dir/enodia"; then
		installed=1
	fi
fi

if [ "$installed" -eq 0 ]; then
	if [ -n "${PREFIX:-}" ] && [ -w "$PREFIX/bin" ]; then
		# No working way to become root: every sandboxed userland-prefix
		# environment (Termux is the common one) looks like this, and
		# $PREFIX is that environment's own "where my stuff goes" variable —
		# not something worth a name-based special case when the two
		# objective facts (no usable sudo, $PREFIX set and writable) already
		# say the same thing.
		install_dir="$PREFIX/bin"
		echo "install.sh: no usable sudo; installing into \$PREFIX/bin ($install_dir) instead"
		install -m 0755 "$tmp/enodia" "$install_dir/enodia"
	else
		echo "install.sh: $install_dir is not writable and no usable sudo is available" \
			"(set \$ENODIA_INSTALL_DIR to a writable directory)" >&2
		exit 1
	fi
fi

echo "install.sh: installed $("$install_dir/enodia" version) to $install_dir/enodia"
