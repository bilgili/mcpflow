#!/bin/sh
# Demo server for clicking through the marketplace. Throwaway data dir/password.
export DATA_DIR=/tmp/mcpflow-demo-data
export ADMIN_PASSWORD=demo
export LOG_LEVEL=info
mkdir -p "$DATA_DIR"
# Resolve the venv from this script, so a git worktree runs its own code.
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec "$ROOT/.venv/bin/python" -m mcpflow.cli serve --host 127.0.0.1 --port 8790
