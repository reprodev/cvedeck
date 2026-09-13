#!/bin/bash
# Install the CveDeck as a systemd service on a Linux host.
#
# Run as root from a checkout of this repository:
#   sudo ./deploy/install.sh
#
# Re-running upgrades an existing installation in place: the code and frontend
# are replaced, the database in /var/lib/cvedeck and the environment file in
# /etc/cvedeck are left alone.
#
# Requires: python3 (>=3.11) with venv, node + npm (to build the frontend).
set -euo pipefail

APP_DIR=/opt/cvedeck
DATA_DIR=/var/lib/cvedeck
CONF_DIR=/etc/cvedeck
ENV_FILE="${CONF_DIR}/cvedeck.env"
SERVICE_USER=cvedeck

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "$(id -u)" != "0" ]; then
    echo "This script must run as root." >&2
    exit 1
fi

for cmd in python3 npm systemctl; do
    command -v "$cmd" >/dev/null || { echo "Missing required command: $cmd" >&2; exit 1; }
done

echo "==> Creating service user and directories"
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi
install -d -o root -g root -m 0755 "$APP_DIR" "$CONF_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$DATA_DIR"

echo "==> Installing backend"
rm -rf "${APP_DIR}/backend"
install -d "${APP_DIR}/backend"
cp -r "${REPO_DIR}/backend/app" "${APP_DIR}/backend/app"
cp "${REPO_DIR}/backend/pyproject.toml" "${REPO_DIR}/backend/README.md" \
   "${REPO_DIR}/backend/requirements.txt" "${APP_DIR}/backend/"

if [ ! -d "${APP_DIR}/venv" ]; then
    python3 -m venv "${APP_DIR}/venv"
fi
"${APP_DIR}/venv/bin/pip" install --upgrade pip
"${APP_DIR}/venv/bin/pip" install --no-cache-dir -r "${APP_DIR}/backend/requirements.txt"
"${APP_DIR}/venv/bin/pip" install --no-cache-dir --no-deps "${APP_DIR}/backend"

echo "==> Building frontend"
(
    cd "${REPO_DIR}/frontend"
    npm ci
    npm run build
)
rm -rf "${APP_DIR}/static"
cp -r "${REPO_DIR}/frontend/dist" "${APP_DIR}/static"

echo "==> Writing configuration"
if [ ! -f "$ENV_FILE" ]; then
    cat > "$ENV_FILE" <<EOF
# CveDeck configuration. See DEPLOYMENT.md for all options.
CVEDECK_DATA_DIR=${DATA_DIR}
CVEDECK_STATIC_DIR=${APP_DIR}/static

# Uncomment to use PostgreSQL instead of the SQLite file in the data directory.
# CVEDECK_DB_URL=postgresql+psycopg://user:password@host/cvedeck

# Uncomment to enable POST /api/sync.
# CVEDECK_ONLINE_DB_URL=postgresql+psycopg://user:password@host/cvedeck

# Threat-intel feeds (CISA KEV, FIRST EPSS) work with no configuration, but are
# refreshed manually -- see the cron this installer sets up below.

# Uncomment to enable OS-level CVE matching against NVD. Unkeyed, NVD allows
# only 5 requests per rolling 30 seconds; a free key raises that to 50:
#   https://nvd.nist.gov/developers/request-an-api-key
# CVEDECK_NVD_ENABLED=true
# CVEDECK_NVD_API_KEY=your-key-here
EOF
    chmod 0640 "$ENV_FILE"
    chown root:"$SERVICE_USER" "$ENV_FILE"
    echo "    wrote ${ENV_FILE}"
else
    echo "    keeping existing ${ENV_FILE}"
fi

chown -R root:root "$APP_DIR"

echo "==> Installing systemd units"
install -m 0644 "${REPO_DIR}/deploy/systemd/cvedeck.service" \
    /etc/systemd/system/cvedeck.service

# Threat-intel feeds are refreshed by a timer rather than in-process: there is
# no scheduler in the application yet, and a stale KEV catalogue silently stops
# flagging newly exploited vulnerabilities.
install -m 0644 "${REPO_DIR}/deploy/systemd/cvedeck-feeds.service" \
    /etc/systemd/system/cvedeck-feeds.service
install -m 0644 "${REPO_DIR}/deploy/systemd/cvedeck-feeds.timer" \
    /etc/systemd/system/cvedeck-feeds.timer

systemctl daemon-reload
systemctl enable --now cvedeck.service
systemctl enable --now cvedeck-feeds.timer

# Populate the caches now rather than leaving the first day unenriched. Failure
# here is not fatal: the timer retries, and until it succeeds the dashboard
# reports the feeds as never-refreshed rather than as "nothing exploited".
echo "==> Fetching threat-intel feeds (KEV, EPSS)"
if ! systemctl start cvedeck-feeds.service; then
    echo "    WARNING: initial feed refresh failed. The timer will retry at 03:00."
    echo "    Exploitation status shows as unknown until it succeeds."
fi

echo
echo "Done. The service listens on 127.0.0.1:8000."
echo "Put a TLS reverse proxy in front of it -- see deploy/nginx/cvedeck.conf.example."
echo "Status:  systemctl status cvedeck"
echo "Logs:    journalctl -u cvedeck -f"
echo "Feeds:   systemctl list-timers cvedeck-feeds.timer"
