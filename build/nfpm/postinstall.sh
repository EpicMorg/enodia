#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Runs after files are unpacked (dpkg's postinst / rpm's %post) —
# ownership is set here rather than baked into the package's own file_info,
# since a .deb's payload carries numeric ownership resolved at *build*
# time, and the enodia system user (preinstall.sh) doesn't exist on the
# build machine — only on whatever machine actually installs this package.
#
# /etc/enodia is root:enodia so the service can read its own config via
# group membership without being able to write it; /opt/enodia and
# /var/enodia are enodia:enodia since they're the service's own state/
# output directories.
set -e

chown root:enodia /etc/enodia
chmod 0750 /etc/enodia

chown enodia:enodia /opt/enodia /var/enodia
chmod 0750 /opt/enodia /var/enodia
