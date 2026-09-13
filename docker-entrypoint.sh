#!/bin/sh
# Container entrypoint: make the data volume writable, then drop privileges.
#
# The image runs as an unprivileged user, but a bind-mounted host directory
# arrives owned by whoever created it. PUID/PGID (the convention used by most
# self-hosted images) let the operator align the container user with the host
# owner instead of chowning the directory by hand.
set -eu

PUID="${PUID:-1000}"
PGID="${PGID:-1000}"
DATA_DIR="${CVEDECK_DATA_DIR:-/data}"

if [ "$(id -u)" != "0" ]; then
    # Already unprivileged (e.g. `docker run --user`); PUID/PGID cannot apply.
    exec "$@"
fi

if [ "$PGID" != "$(id -g appuser)" ]; then
    groupmod -o -g "$PGID" appuser
fi
if [ "$PUID" != "$(id -u appuser)" ]; then
    usermod -o -u "$PUID" appuser
fi

mkdir -p "$DATA_DIR"
# Only the volume is chowned; the read-only application code stays root-owned.
chown -R "$PUID:$PGID" "$DATA_DIR"

exec gosu "$PUID:$PGID" "$@"
