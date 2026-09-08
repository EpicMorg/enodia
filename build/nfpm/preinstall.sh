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
# If 1337 is already taken by something else on a given machine, the
# commands below fail loudly rather than silently falling back to a
# different id, which is the right failure mode for something that must
# stay fixed.
#
# Portable across all three package formats nfpm builds here: deb/rpm
# targets always have GNU shadow-utils (groupadd/useradd), but apk targets
# Alpine, whose base image ships neither — only busybox's addgroup/adduser,
# with a different flag syntax. groupadd's presence is what picks the
# branch, not a distro check, since that's the actual thing that varies.
set -e

ENODIA_UID=1337
ENODIA_GID=1337

# Alpine's nologin is /sbin/nologin (a busybox multi-call symlink);
# Debian/RHEL both ship /usr/sbin/nologin instead.
if [ -x /usr/sbin/nologin ]; then
	NOLOGIN=/usr/sbin/nologin
else
	NOLOGIN=/sbin/nologin
fi

if command -v groupadd >/dev/null 2>&1; then
	getent group enodia >/dev/null 2>&1 || groupadd --system --gid "$ENODIA_GID" enodia
	getent passwd enodia >/dev/null 2>&1 || useradd --system --uid "$ENODIA_UID" --gid "$ENODIA_GID" \
		--no-create-home --home-dir /opt/enodia --shell "$NOLOGIN" enodia
else
	getent group enodia >/dev/null 2>&1 || addgroup -S -g "$ENODIA_GID" enodia
	getent passwd enodia >/dev/null 2>&1 || adduser -S -D -H \
		-h /opt/enodia -s "$NOLOGIN" -G enodia -u "$ENODIA_UID" enodia
fi
