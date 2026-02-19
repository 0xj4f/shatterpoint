# ── Build stage ──────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app

# Install build deps first (layer cache)
COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir build \
    && python -m build --wheel --outdir /app/dist

# ── Runtime stage ────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL maintainer="0xj4f"
LABEL description="0xj4f-webcrawler — OSCP Recon Attack Surface Mapper"

WORKDIR /app

# Install the built wheel + runtime deps only
COPY --from=builder /app/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl \
    && rm -rf /tmp/*.whl

# Default output directory
RUN mkdir -p /app/output
VOLUME ["/app/output"]

ENTRYPOINT ["0xj4f-webcrawler"]
CMD ["--help"]

# ── Test stage (used by CI only) ─────────────────────────
FROM python:3.12-slim AS test

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ src/
COPY tests/ tests/

RUN pip install --no-cache-dir ".[dev]"

CMD ["pytest", "tests/", "-v"]
