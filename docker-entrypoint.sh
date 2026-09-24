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

# Everything the application writes -- the database, its journal -- is readable
# by its own user and group and nobody else. The database is the fleet's full
# software inventory, token hashes and SSH host-key pins; before 0.8.13 it was
# written 0644, readable by every account on the Docker host.
umask 0027

if [ "$(id -u)" != "0" ]; then
    # Already unprivileged (e.g. `docker run --user`); PUID/PGID cannot apply.
    exec "$@"
fi

# PUID=0 or PGID=0 would silently run the application as root, which is the one
# thing the privilege drop below exists to prevent.
if [ "${CVEDECK_ALLOW_ROOT:-}" != "1" ] && { [ "$PUID" = "0" ] || [ "$PGID" = "0" ]; }; then
    echo "cvedeck: refusing PUID=$PUID PGID=$PGID -- that runs CveDeck as root." >&2
    echo "cvedeck: set PUID/PGID to the owner of the data directory (id -u / id -g)," >&2
    echo "cvedeck: or CVEDECK_ALLOW_ROOT=1 if you really mean it." >&2
    exit 1
fi

# Everything below chowns DATA_DIR recursively, so it must be a data directory
# and not the image itself.
case "$DATA_DIR" in
    /|/app|/app/*|/usr|/usr/*|/bin|/sbin|/etc|/etc/*|/lib|/lib/*|/var|/root|/proc|/sys|/dev)
        echo "cvedeck: refusing CVEDECK_DATA_DIR=$DATA_DIR -- it is not a data directory." >&2
        exit 1
        ;;
esac

if [ "$PGID" != "$(id -g appuser)" ]; then
    groupmod -o -g "$PGID" appuser
fi
if [ "$PUID" != "$(id -u appuser)" ]; then
    usermod -o -u "$PUID" appuser
fi

mkdir -p "$DATA_DIR"
# Only the volume is chowned; the read-only application code stays root-owned.
chown -R "$PUID:$PGID" "$DATA_DIR"
# And closed to other users, including files an older release left 0644.
chmod -R o-rwx "$DATA_DIR"

exec gosu "$PUID:$PGID" "$@"
