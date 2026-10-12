# shatterpoint Dockerfile
#
# CI builds the wheel on the runner (so hatch-vcs can read the git tag
# and stamp the version) and this image just installs it. Multi-arch
# friendly (the wheel is `py3-none-any`). Two targets:
#
#   runtime  lean image — what the release workflow publishes
#   browser  runtime + Playwright + headless Chromium, for --browser
#
# Build context expectation:
#   - ./dist/shatterpoint-<version>-py3-none-any.whl exists
#
# To build locally:
#   python -m build --wheel
#   docker build --target runtime -t shatterpoint:dev .
#   docker build --target browser -t shatterpoint:browser .

FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="shatterpoint"
LABEL org.opencontainers.image.description="Web Recon Attack Surface Mapper"
LABEL org.opencontainers.image.authors="0xj4f"
LABEL org.opencontainers.image.source="https://github.com/0xj4f/shatterpoint"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Install the pre-built wheel produced by the CI runner. Using
# --no-cache-dir keeps the layer small; the wheel itself is removed
# after install to drop another ~1MB.
COPY dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl \
    && rm -rf /tmp/*.whl

# Reports are written here by default.
RUN mkdir -p /app/output
VOLUME ["/app/output"]

ENTRYPOINT ["shatterpoint"]
CMD ["--help"]


# ── browser: adds what --browser needs ──────────────────────────────
# Playwright (same as the `browser` extra in pyproject.toml), the
# headless-only Chromium build, and the system libraries it links to.
FROM runtime AS browser

RUN pip install --no-cache-dir "playwright>=1.49" \
    && playwright install --with-deps --only-shell chromium \
    && rm -rf /var/lib/apt/lists/*
