#!/bin/sh
# Demo server for clicking through the marketplace. Throwaway data dir/password.
export DATA_DIR=/tmp/mcpflow-demo-data
export LOG_LEVEL=info
mkdir -p "$DATA_DIR"
# Resolve the venv from this script, so a git worktree runs its own code.
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# The admin password `demo`: write the hash file the way the README hand path
# says (a private temporary file, then `mv`). The server applies it at start.
(
  umask 077
  "$ROOT/.venv/bin/python" -m mcpflow.cli hash-password demo > "$DATA_DIR/.admin-password.hash.tmp"
)
mv "$DATA_DIR/.admin-password.hash.tmp" "$DATA_DIR/admin-password.hash"
exec "$ROOT/.venv/bin/python" -m mcpflow.cli serve --host 127.0.0.1 --port 8790
