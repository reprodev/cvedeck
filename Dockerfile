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
FROM node:22-alpine AS frontend

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
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install pinned dependencies before the source so code changes do not
# invalidate the dependency layer.
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

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
