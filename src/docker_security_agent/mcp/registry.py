"""MCP server registry: build servers from config, health-check them, set them up.

Responsibilities:

* ``check_docker_endpoint`` - make sure ``docker_host`` is the read-only proxy
  (not the raw socket) and that the proxy actually filters requests.
* ``ensure_server_setup``   - install the trivy-mcp plugin on demand (the
  "dynamic install" for servers that are not Python packages; docker-mcp-server
  needs nothing because ``uvx`` fetches the pinned version itself).
* ``trivy_db_status`` / ``download_trivy_db`` - trivy-mcp always runs Trivy
  with ``--skip-update``, so the vulnerability DB must already be present.
* ``build_servers``         - create one ``GuardedMCPServer`` per enabled server.
* ``connect``               - connect a set of servers with the SDK's
  ``MCPServerManager``; servers that fail to start are dropped (graceful
  degradation) and reported instead of crashing the run.
* ``inspect_server_tools``  - list a connected server's tools and compare them
  with the approved list (``docker-audit mcp check``).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx
from agents.mcp import MCPServerManager

from docker_security_agent.config import MCPServerConfig, Settings
from docker_security_agent.mcp.policy import ToolPolicy
from docker_security_agent.mcp.recorder import ToolCallRecorder
from docker_security_agent.mcp.redaction import Redactor
from docker_security_agent.mcp.servers import GuardedMCPServer

# ---------------------------------------------------------------------------
# Docker endpoint / proxy checks
# ---------------------------------------------------------------------------


@dataclass
class DockerEndpointStatus:
    docker_host: str
    is_tcp: bool
    reachable: bool = False
    filtered: bool = False  # True = proxy refused a request it should refuse
    docker_version: str = ""
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def _http_base(docker_host: str) -> str:
    """tcp://127.0.0.1:2375 -> http://127.0.0.1:2375"""
    parsed = urlparse(docker_host)
    return f"http://{parsed.hostname}:{parsed.port or 2375}"


def check_docker_endpoint(settings: Settings, timeout: float = 5.0) -> DockerEndpointStatus:
    """Verify that the configured Docker endpoint is the read-only proxy.

    The filtering test is harmless: it sends ``GET /secrets``. Through the
    proxy (SECRETS=0) the answer is HTTP 403. A raw Docker daemon would answer
    503/200 instead. We never send a POST to find out - on a raw socket a
    POST could actually change something.
    """
    host = settings.mcp.docker_host
    status = DockerEndpointStatus(docker_host=host, is_tcp=host.startswith("tcp://"))

    if not status.is_tcp:
        if settings.mcp.require_proxy:
            status.problems.append(
                f"docker_host '{host}' is not a tcp:// proxy address. Start the read-only "
                "proxy (deploy/socket-proxy/compose.yml) and point docker_host at it, or set "
                "require_proxy: false (NOT recommended)."
            )
        return status

    base = _http_base(host)
    try:
        with httpx.Client(timeout=timeout) as client:
            version = client.get(f"{base}/version")
            status.reachable = version.status_code == 200
            if status.reachable:
                status.docker_version = version.json().get("Version", "")
            probe = client.get(f"{base}/secrets")
            status.filtered = probe.status_code == 403
    except httpx.HTTPError as exc:
        status.problems.append(f"Cannot reach Docker proxy at {base}: {exc}")
        return status

    if not status.reachable:
        status.problems.append(f"Docker proxy at {base} did not answer /version with 200.")
    if not status.filtered and settings.mcp.require_proxy:
        status.problems.append(
            f"{base} did not refuse GET /secrets with 403, so it does not look like the "
            "read-only socket proxy. Refusing to continue (require_proxy: true)."
        )
    return status


# ---------------------------------------------------------------------------
# Server setup (dynamic install of the Trivy plugin) and the Trivy DB
# ---------------------------------------------------------------------------


@dataclass
class SetupStatus:
    server: str
    command_found: bool
    ready: bool
    installed_now: bool = False
    message: str = ""


def ensure_server_setup(cfg: MCPServerConfig, install: bool) -> SetupStatus:
    """Make sure a server's executable (and plugin, if any) is available.

    ``install=True`` runs the configured install command when the check fails.
    """
    if shutil.which(cfg.command) is None:
        hint = (
            "Install uv: https://docs.astral.sh/uv/"
            if cfg.command == "uvx"
            else ("Install Trivy: brew install trivy" if cfg.command == "trivy" else "")
        )
        return SetupStatus(cfg.name, False, False, message=f"'{cfg.command}' not on PATH. {hint}")

    setup = cfg.setup
    if setup is None or not setup.check_command:
        return SetupStatus(cfg.name, True, True, message="no setup required")

    def _check() -> bool:
        out = subprocess.run(setup.check_command, capture_output=True, text=True, timeout=60)
        return out.returncode == 0 and setup.check_contains in (out.stdout + out.stderr)

    if _check():
        return SetupStatus(cfg.name, True, True, message="ready")
    if not (install and setup.auto_install and setup.install_command):
        return SetupStatus(
            cfg.name,
            True,
            False,
            message=f"not installed; run: {' '.join(setup.install_command)}",
        )
    proc = subprocess.run(setup.install_command, capture_output=True, text=True, timeout=600)
    if proc.returncode != 0 or not _check():
        return SetupStatus(
            cfg.name, True, False, message=f"install failed: {proc.stderr.strip()[-500:]}"
        )
    return SetupStatus(cfg.name, True, True, installed_now=True, message="installed")


def trivy_db_status() -> dict[str, Any]:
    """Return Trivy's vulnerability-DB metadata (empty dict if not downloaded)."""
    if shutil.which("trivy") is None:
        return {}
    proc = subprocess.run(
        ["trivy", "version", "--format", "json"], capture_output=True, text=True, timeout=60
    )
    if proc.returncode != 0:
        return {}
    try:
        info = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {}
    db = info.get("VulnerabilityDB") or {}
    return {"trivy_version": info.get("Version", ""), **db}


def download_trivy_db() -> tuple[bool, str]:
    """Download/refresh Trivy's vulnerability DB (needs internet, ~120 MB)."""
    proc = subprocess.run(
        ["trivy", "image", "--download-db-only", "--quiet"],
        capture_output=True,
        text=True,
        timeout=900,
    )
    return proc.returncode == 0, (proc.stderr or proc.stdout).strip()[-500:]


# ---------------------------------------------------------------------------
# Building and connecting servers
# ---------------------------------------------------------------------------


def build_servers(
    settings: Settings,
    policy: ToolPolicy,
    redactor: Redactor,
    recorder: ToolCallRecorder,
    roles: set[str] | None = None,
) -> list[GuardedMCPServer]:
    """Create (but do not connect) a GuardedMCPServer for each enabled server."""
    servers = []
    for cfg in settings.mcp.enabled_servers():
        if roles and cfg.role not in roles:
            continue
        servers.append(
            GuardedMCPServer(
                cfg,
                docker_host=settings.mcp.docker_host,
                policy=policy,
                redactor=redactor,
                recorder=recorder,
                max_result_chars=settings.agent.limits.max_tool_result_chars,
            )
        )
    return servers


def connect(servers: list[GuardedMCPServer]) -> MCPServerManager:
    """Return an MCPServerManager; use it as ``async with connect(...) as mgr``.

    ``drop_failed_servers=True`` means a broken server is removed from
    ``mgr.active_servers`` and listed in ``mgr.failed_servers`` / ``mgr.errors``
    instead of aborting the whole run. The generous connect timeout covers the
    first ``uvx`` launch, which downloads docker-mcp-server.
    """
    return MCPServerManager(
        servers,
        connect_timeout_seconds=180,
        cleanup_timeout_seconds=15,
        drop_failed_servers=True,
        connect_in_parallel=True,
    )


@dataclass
class ToolInventory:
    server: str
    available: list[str]  # every tool the server registered
    approved: list[str]  # approved in config
    exposed: list[str]  # approved AND available (what the agent sees)
    missing: list[str]  # approved but NOT offered by the server
    schema_problems: list[str]


async def inspect_server_tools(server: GuardedMCPServer) -> ToolInventory:
    """Compare the tools a connected server offers with the approved list.

    ``list_tools`` on the SDK object is already filtered, so we go through the
    underlying MCP session to see the full, unfiltered tool surface.
    """
    assert server.session is not None, "server must be connected"
    listed = await server.session.list_tools()
    all_tools = {t.name: t for t in listed.tools}
    approved = server.config.allowed_tools
    exposed = [t for t in approved if t in all_tools]
    missing = [t for t in approved if t not in all_tools]
    problems = []
    for name in exposed:
        schema = all_tools[name].input_schema or {}
        if schema.get("type") != "object":
            problems.append(f"{name}: input schema is not a JSON object schema")
    return ToolInventory(
        server=server.name,
        available=sorted(all_tools),
        approved=list(approved),
        exposed=exposed,
        missing=missing,
        schema_problems=problems,
    )
