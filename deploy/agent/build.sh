#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Build the agent images (runtime + test) with git provenance.
#
# Run manifests record the framework's git commit and whether tracked files
# had uncommitted changes. The image contains no .git, so this records both at
# build time (Dockerfile build args BUILD_COMMIT / BUILD_DIRTY). A plain
# `docker compose build` also works; manifests then say commit "unknown".
#
# Extra arguments go to `docker compose build` (e.g. --no-cache).
# ---------------------------------------------------------------------------
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

AGENT_BUILD_COMMIT=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || true)
if [[ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=no 2>/dev/null)" ]]; then
  AGENT_BUILD_DIRTY=true
else
  AGENT_BUILD_DIRTY=false
fi
export AGENT_BUILD_COMMIT AGENT_BUILD_DIRTY

echo "[build] commit ${AGENT_BUILD_COMMIT:-unknown} dirty=$AGENT_BUILD_DIRTY" >&2
exec docker compose -f "$REPO_ROOT/deploy/agent/compose.yml" --profile test build "$@"
