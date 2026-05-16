# shatterpoint Dockerfile
#
# CI builds the wheel on the runner (so hatch-vcs can read the git tag
# and stamp the version) and this image just installs it. Single stage,
# minimal layers, multi-arch friendly (the wheel is `py3-none-any`).
#
# Build context expectation:
#   - ./dist/shatterpoint-<version>-py3-none-any.whl exists
#
# To build locally:
#   python -m build --wheel
#   docker build -t shatterpoint:dev .

FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="shatterpoint"
LABEL org.opencontainers.image.description="OSCP Recon Attack Surface Mapper"
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
