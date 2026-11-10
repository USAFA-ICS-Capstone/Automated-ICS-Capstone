# ---------------------------------------------------------------------------
# Container image for the Docker Security Assessment Agent (docker-audit).
#
# The image packages the SAME code, config and pinned tools the host workflow
# uses; nothing about the agent's behaviour changes:
#   - Python 3.12 + the exact dependency versions from uv.lock
#   - uv/uvx, which launches docker-mcp-server==2.2.7 (pre-cached at build time)
#   - Trivy 0.75.0 + the trivy-mcp plugin mcp@v0.0.20
#
# NOT in the image: the LLM (Ollama stays on the host), the Docker socket (the
# agent only reaches Docker through the read-only proxy), any secrets.
#
# Targets:
#   runtime (default)  the agent; ENTRYPOINT is `docker-audit`
#   test               runtime + dev dependencies + tests; runs pytest
#
# Build / run through Compose: see deploy/agent/compose.yml and the README.
# ---------------------------------------------------------------------------

# Pinned tool images (versions match the host setup in the README).
FROM ghcr.io/astral-sh/uv:0.12.19 AS uv
FROM aquasec/trivy:0.75.0 AS trivy

# Build-only stage: `trivy plugin install` needs git, which the runtime image
# does not ship. Only the installed plugin directory is copied out.
FROM python:3.12-slim-bookworm AS trivy-plugin
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
RUN trivy plugin install mcp@v0.0.20

FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    HOME=/home/agent

# Phase 2 (verify) MCP servers: where the baked clones live and the PLC target.
# MODBUS_HOST is overridden per deployment (deploy/agent/compose.grfics.example.yml).
ENV NMAPMCP_DIR=/opt/nmapmcp \
    MODBUS_MCP_DIR=/opt/modbus-mcp \
    MODBUS_TYPE=tcp \
    MODBUS_HOST=plc \
    MODBUS_PORT=502

COPY --from=uv /uv /uvx /usr/local/bin/
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

# Unprivileged user. MCP server subprocesses inherit only HOME/PATH/USER/...
# (not UV_* variables), so their caches live under HOME.
RUN groupadd --gid 10001 agent \
 && useradd --uid 10001 --gid agent --create-home --home-dir /home/agent \
        --shell /usr/sbin/nologin agent

WORKDIR /app

# Dependencies first (cached layer), then the project itself. The venv is
# owned by root and read-only for the agent user.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --no-cache --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --no-cache --frozen --no-dev --no-editable
COPY config ./config

COPY --from=trivy-plugin --chown=agent:agent /root/.trivy /home/agent/.trivy
RUN mkdir -p /app/data /app/outputs && chown agent:agent /app/data /app/outputs

# Phase 2 (verify): the nmap binary, plus pinned clones of the two active MCP
# servers (not on PyPI, so they are baked in by commit rather than `uvx`-pinned).
# NmapMCP (0xPratikPatil) and modbus-mcp (kukapay) are launched at runtime with
# `uv --directory <dir> run ...`; their venvs are synced below as the agent user.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap git \
 && rm -rf /var/lib/apt/lists/* \
 && git clone https://github.com/0xPratikPatil/NmapMCP.git /opt/nmapmcp \
 && git -C /opt/nmapmcp checkout 0971a5221d6f0185c7e90ceaa31223cacfd752e5 \
 && git clone https://github.com/kukapay/modbus-mcp.git /opt/modbus-mcp \
 && git -C /opt/modbus-mcp checkout 0ac2c79be9de37fa59b887c9d164305219773f76 \
 && chown -R agent:agent /opt/nmapmcp /opt/modbus-mcp

USER agent

# Pre-install the MCP servers so a run never downloads code:
#  - trivy-mcp plugin into ~/.trivy/plugins (copied above; what `docker-audit
#    setup` would install)
#  - docker-mcp-server==2.2.7 into uv's cache (what the first `uvx` launch
#    would do). It requires Python >= 3.14, so uv fetches a managed CPython
#    3.14.7 for it (the same version uvx uses on the host); the agent itself
#    stays on 3.12.
# Then switch uv to offline mode: at runtime `uvx docker-mcp-server==2.2.7`
# resolves from this cache only, so the pinned version is the one that runs.
RUN trivy plugin list | grep -q mcp \
 && uv python install 3.14.7 \
 && uvx --from docker-mcp-server==2.2.7 python -c "import docker_mcp" \
 # Phase 2: install the two verify servers into their own venvs (fetches their
 # managed CPythons: nmap 3.13, modbus 3.10). Each gets its OWN venv; the
 # image-wide UV_PROJECT_ENVIRONMENT (/opt/venv) must be overridden or uv reuses it.
 # mcp is pinned to 1.30.0: the servers' code is written for the mcp v1 API
 # (mcp.server.fastmcp.FastMCP, renamed/removed in mcp 2.x), while their own locks
 # pin 1.6.0 — too old to complete the MCP handshake with this image's client
 # (mcp 2.3.0, via openai-agents). 1.30.0 is the newest v1 that keeps FastMCP AND
 # interoperates with the 2.3.0 client. `uv add` re-resolves and installs the venv.
 && UV_PROJECT_ENVIRONMENT=/opt/nmapmcp/.venv uv --directory /opt/nmapmcp add "mcp[cli]==1.30.0" \
 && UV_PROJECT_ENVIRONMENT=/opt/modbus-mcp/.venv uv --directory /opt/modbus-mcp add "mcp[cli]==1.30.0" \
 && mkdir -p /home/agent/.cache/trivy /home/agent/.config/uv \
 && printf 'offline = true\npython-downloads = "never"\n' > /home/agent/.config/uv/uv.toml

# Persistent state (mount volumes here; see deploy/agent/compose.yml):
#   /app/data                 SQLite (assessments.db, agent_sessions.db), range baselines
#   /app/outputs              per-run agent_report / deterministic_report / comparison
#                             (.json + .md) and manifest.json
#   /home/agent/.cache/trivy  Trivy vulnerability DB + layer cache
VOLUME ["/app/data", "/app/outputs", "/home/agent/.cache/trivy"]

# Code provenance for run manifests: the image has no .git, so the build
# records the commit (deploy/agent/build.sh passes these; empty = "unknown").
ARG BUILD_COMMIT=""
ARG BUILD_DIRTY=""
ENV DOCKER_AUDIT_BUILD_COMMIT=$BUILD_COMMIT \
    DOCKER_AUDIT_BUILD_DIRTY=$BUILD_DIRTY

ENTRYPOINT ["docker-audit"]
# Default: preflight validation of every dependency (config, proxy, MCP
# servers, Trivy DB, Ollama model). Exits non-zero if anything is missing.
CMD ["doctor"]

# ---------------------------------------------------------------------------
FROM runtime AS test

USER root
# perl provides `shasum`, used by deploy/grfics/range.sh (a host-side operator
# tool that is only exercised by its tests here, never run by the agent).
RUN apt-get update \
 && apt-get install -y --no-install-recommends perl \
 && rm -rf /var/lib/apt/lists/*
# --no-config: ignore the agent user's offline uv.toml for this build step.
RUN uv sync --no-config --no-cache --frozen --no-editable
COPY tests ./tests
COPY deploy ./deploy
USER agent

ENTRYPOINT ["python", "-m", "pytest", "-p", "no:cacheprovider"]
CMD ["-q"]
