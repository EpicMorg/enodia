#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Runs before files are unpacked (dpkg's preinst / rpm's %pre) — creates the
# dedicated system user/group so postinstall.sh can chown to them by name
# once the directories actually exist. Idempotent: reinstalling or
# upgrading must not fail because the user is already there.
#
# Fixed uid/gid 1337 rather than whatever the system's next free system id
# happens to be: numeric ownership then matches across every machine this
# package is installed on (including build/docker/Dockerfile's image,
# which installs this same .deb), which matters for bind-mounted
# /etc/enodia, /opt/enodia, /var/enodia — a host-side chown to 1337:1337
# lines up without needing to know or match a name inside the container.
# If 1337 is already taken by something else on a given machine, useradd/
# groupadd fail loudly rather than silently falling back to a different
# id, which is the right failure mode for something that must stay fixed.
set -e

ENODIA_UID=1337
ENODIA_GID=1337

if ! getent group enodia >/dev/null 2>&1; then
	groupadd --system --gid "$ENODIA_GID" enodia
fi

if ! getent passwd enodia >/dev/null 2>&1; then
	useradd --system --uid "$ENODIA_UID" --gid "$ENODIA_GID" \
		--no-create-home --home-dir /opt/enodia \
		--shell /usr/sbin/nologin enodia
fi
