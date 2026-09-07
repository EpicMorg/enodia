#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Runs before files are unpacked (dpkg's preinst / rpm's %pre) — creates the
# dedicated system user/group so postinstall.sh can chown to them by name
# once the directories actually exist. Idempotent: reinstalling or
# upgrading must not fail because the user is already there.
set -e

if ! getent group enodia >/dev/null 2>&1; then
	groupadd --system enodia
fi

if ! getent passwd enodia >/dev/null 2>&1; then
	useradd --system --no-create-home --home-dir /opt/enodia \
		--shell /usr/sbin/nologin --gid enodia enodia
fi
