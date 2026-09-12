# syntax=docker/dockerfile:1

FROM node:22-bookworm-slim AS node

# Build the mcpflow wheel from source — no PyPI publish, no wheels build-context.
FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /usr/local/bin/uv
WORKDIR /src
COPY . .
RUN uv build --wheel --out-dir /wheels

FROM python:3.12-slim

ARG PIP_INDEX_URL=https://pypi.org/simple/

# The copied node binary needs libstdc++6. git and its CA certificates are for
# a child whose spec names a git `source`: `npx --package=<source>` and
# `uvx --from <source>` clone it at the first start, so without git such a child
# cannot run at all.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libstdc++6 \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# node, npm, npx from the node stage.
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

# uv and uvx (pinned; bump on purpose).
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /uvx /usr/local/bin/

# Install mcpflow from the source-built wheel; its dependencies come from the index.
RUN --mount=type=bind,from=builder,source=/wheels,target=/wheels \
    pip install --no-cache-dir --index-url "$PIP_INDEX_URL" --find-links /wheels mcpflow

# Non-root user and a writable data volume.
RUN useradd -u 1000 -m -s /bin/sh app \
    && mkdir -p /data \
    && chown 1000:1000 /data
VOLUME /data

ENV DATA_DIR=/data \
    HOST=0.0.0.0 \
    PORT=8000 \
    UV_CACHE_DIR=/data/cache/uv \
    npm_config_cache=/data/cache/npm

USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"
CMD ["mcpflow", "serve"]
