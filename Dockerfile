# CveDeck -- single all-in-one image.
#
# Stage 1 builds the React frontend; stage 2 installs the FastAPI backend and
# serves both the API and the built frontend from one origin on port 8000, which
# is what the frontend expects (it calls /api/... relative to its own origin).
#
# State lives in /data -- mount it to keep the database across restarts:
#   docker run -p 3325:8000 -v /srv/cvedeck:/data cvedeck:latest

# ---------------------------------------------------------------------------
# Stage 1: build the frontend
# ---------------------------------------------------------------------------
# Built once, on the build machine's own architecture, whatever platform the
# image targets. The output is static HTML, CSS and JavaScript -- identical for
# amd64 and arm64 -- so there is nothing to gain from building it under qemu,
# and a lot to lose: the v0.7.0 release hung for over an hour when `npm ci`
# crashed with "Illegal instruction" under arm64 emulation and never exited.
FROM --platform=$BUILDPLATFORM node:24-alpine AS frontend

WORKDIR /build

# Copy manifests first so `npm ci` is cached until dependencies actually change.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
# Pinned to 3.12: the project requires >=3.11, and 3.12 has the widest wheel
# coverage for paramiko/pywinrm/psycopg.
FROM python:3.12-slim AS runtime

# gosu drops privileges in the entrypoint after fixing up /data ownership;
# curl backs the HEALTHCHECK below.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gosu curl \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install pinned dependencies before the source so code changes do not
# invalidate the dependency layer.
# pip itself is pinned, like everything else in the image: the base image
# ships whatever pip was current when it was built.
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir pip==26.2.1 \
    && pip install --no-cache-dir -r requirements.txt

COPY backend/pyproject.toml backend/README.md backend/alembic.ini ./
COPY backend/app ./app
RUN pip install --no-cache-dir --no-deps .

# The built dashboard, served by the API at the root path.
COPY --from=frontend /build/dist /app/static

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Non-root by default; the entrypoint remaps this uid/gid to PUID/PGID so a
# bind-mounted host directory stays writable whatever its ownership.
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid 1000 --no-create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /data \
    && chown appuser:appuser /data

ENV CVEDECK_DATA_DIR=/data \
    CVEDECK_STATIC_DIR=/app/static \
    PUID=1000 \
    PGID=1000

VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# A single worker is deliberate: the SQLAlchemy engine is a process-wide
# singleton over SQLite, which allows only one writer. Scaling to multiple
# workers requires pointing CVEDECK_DB_URL at PostgreSQL first.
CMD ["uvicorn", "app.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
