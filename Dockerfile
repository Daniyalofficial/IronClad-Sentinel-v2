# IronClad Sentinel server image.
#
# Multi-stage: the builder resolves and wheels the dependencies, the runtime
# image carries only what is needed to serve. Runs as a non-root user, and
# the scanner never executes scanned code -- it only parses it.
FROM python:3.11-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY ironclad ./ironclad
RUN python -m pip wheel --wheel-dir /wheels ".[server]"

FROM python:3.11-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    IRONCLAD_LOG_LEVEL=INFO \
    IRONCLAD_SCAN_ROOT=/work

# curl is used by the container healthcheck; nothing else is installed.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system ironclad \
    && useradd --system --gid ironclad --home-dir /app --shell /usr/sbin/nologin ironclad

COPY --from=builder /wheels /wheels
RUN python -m pip install --no-index --find-links /wheels /wheels/*.whl \
    && rm -rf /wheels

WORKDIR /app
COPY --chown=ironclad:ironclad scripts/ ./scripts/
COPY --chown=ironclad:ironclad docs/ ./docs/

# /work is the scan root: mount the repositories you want scanned here.
# Everything under it is only read and parsed.
RUN mkdir -p /work /data && chown -R ironclad:ironclad /work /data
VOLUME ["/work"]

USER ironclad
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/ready || exit 1

# Migrations run on startup (idempotent and checksummed). Use the `worker`
# profile in compose/k8s to run the scan worker instead of the API.
ENTRYPOINT ["/app/scripts/container-entrypoint.sh"]
CMD ["api"]
