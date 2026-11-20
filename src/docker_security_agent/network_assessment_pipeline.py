"""Phase 2 (live network exposure) run, end to end.

``run_network_assessment`` is what ``docker-audit network`` calls. It runs the
NetworkExposureAgent INDEPENDENTLY of the Phase-1 assessment: it does not read
any Phase-1 report, findings or claims. It only:

    1. starts the Phase-2 MCP servers (nmap + modbus),
    2. hands the agent the lab's own network layout from config (the nmap
       ``allowed_cidrs`` / ``allowed_hostnames`` and the Modbus endpoint) - the
       same neutral facts the safety policy enforces, never Phase-1 output,
    3. lets it sweep the permitted subnets, service-scan live hosts and read
       Modbus registers, recording one section per host,
    4. writes outputs/<run_id>/network_report.{json,md} in the SAME shape as the
       Phase-1 agent report, so the two can be reconciled.

Both agents pursue one goal - how close can an attacker get to the physical
process - by two independent methods (static Docker metadata vs. live network).
"""

from __future__ import annotations

import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from agents import set_tracing_disabled

from docker_security_agent.agents.context_filter import ContextFilter
from docker_security_agent.agents.network_assessment import (
    NET_PROMPT_VERSION,
    build_exposure_agent,
    build_exposure_input,
)
from docker_security_agent.agents.network_tools import build_network_tools
from docker_security_agent.agents.security_assessment import merge_sections, run_agent
from docker_security_agent.config import ConfigError, Settings
from docker_security_agent.llm.capabilities import check_profile
from docker_security_agent.llm.factory import build_model
from docker_security_agent.mcp.evidence import EvidenceStore
from docker_security_agent.mcp.policy import ToolPolicy
from docker_security_agent.mcp.recorder import ToolCallRecorder
from docker_security_agent.mcp.registry import build_servers, connect
from docker_security_agent.mcp.servers import GuardedMCPServer
from docker_security_agent.memory.sessions import open_session
from docker_security_agent.reporting.agent_report import (
    build_agent_report,
    render_agent_markdown,
)
from docker_security_agent.reporting.generator import write_files
from docker_security_agent.schemas.reports import (
    AgentAssessment,
    MCPServerInfo,
    ModelInfo,
    RunMetrics,
)

# nmap (reachability) + modbus (ICS protocol) - the two live-network servers.
PHASE2_ROLES = {"network_scanner", "ics_protocol"}

# Written alongside the Phase-1 agent_report.{json,md} in the same run folder.
NETWORK_REPORT = "network_report"
PLAN_HISTORY = "plan_history.json"  # every version of the agent's own plan (h7)


class NetworkAssessmentAborted(Exception):
    """The run cannot proceed (servers down, no model, etc.)."""


@dataclass
class NetworkOptions:
    model_profile: str | None = None
    run_id: str | None = None  # None -> a fresh run id is generated
    skip_model_check: bool = False
    progress: Callable[[str], None] | None = None
    notes: list[str] = field(default_factory=list)


@dataclass
class NetworkResult:
    run_id: str
    status: str
    report_md_path: Path
    findings: int


def _say(opts: NetworkOptions, message: str) -> None:
    if opts.progress:
        opts.progress(message)


def new_run_id() -> str:
    return f"net-{datetime.now(UTC):%Y%m%d-%H%M%S}-{secrets.token_hex(2)}"


def _modbus_target(settings: Settings) -> str:
    """The PLC Modbus endpoint, from the ics_protocol server's env (default plc:502)."""
    for server in settings.mcp.servers.values():
        if server.role == "ics_protocol":
            # ezhuk modbus-mcp settings (env prefix MODBUS_MCP_, nested delimiter __)
            host = server.env.get("MODBUS_MCP_MODBUS__HOST") or "plc"
            port = server.env.get("MODBUS_MCP_MODBUS__PORT") or "502"
            return f"{host}:{port}"
    return "plc:502"


async def run_network_assessment(settings: Settings, opts: NetworkOptions) -> NetworkResult:
    set_tracing_disabled(not settings.agent.tracing_enabled)
    run_id = opts.run_id or new_run_id()

    # 1. model
    profile = settings.get_profile(opts.model_profile)
    if not opts.skip_model_check:
        _say(opts, f"Checking model profile '{profile.name}' ({profile.provider}/{profile.model})")
        check = await check_profile(profile)
        if not check.ok:
            raise ConfigError(
                f"Model profile '{profile.name}' is not usable:\n  - "
                + "\n  - ".join(check.errors or ["unknown problem"])
            )
    bundle = build_model(profile)
    model_info = ModelInfo(
        profile=profile.name,
        provider=profile.provider,
        model=profile.model,
        settings=profile.public_dict(),
    )

    # 2. Phase-2 MCP servers (nmap + modbus) only
    started_at = datetime.now(UTC)
    t_start = time.perf_counter()
    recorder = ToolCallRecorder(settings.agent.limits.max_tool_calls)
    policy = ToolPolicy(settings.mcp)
    servers = build_servers(settings, policy, recorder, roles=PHASE2_ROLES)
    if not servers:
        raise NetworkAssessmentAborted(
            "No Phase-2 servers are enabled (need roles network_scanner + ics_protocol in "
            "config/mcp_servers.yaml)."
        )
    _say(opts, "Starting Phase-2 MCP servers: " + ", ".join(s.name for s in servers))

    # 3. neutral targets from config (NOT from any Phase-1 report)
    nmap_policy = settings.mcp.argument_policy.nmap
    allowed_cidrs = list(nmap_policy.allowed_cidrs)
    allowed_hostnames = list(nmap_policy.allowed_hostnames)
    modbus_target = _modbus_target(settings)

    errors = list(opts.notes)
    assessment: AgentAssessment | None = None
    outcome_status = "error"
    usage: dict = {}

    async with connect(servers) as manager:
        active: list[GuardedMCPServer] = list(manager.active_servers)  # type: ignore[arg-type]
        infos: list[MCPServerInfo] = []
        for s in servers:
            err = manager.errors.get(s)
            infos.append(
                MCPServerInfo(
                    name=s.name,
                    role=s.config.role,
                    command=" ".join([s.config.command, *s.config.args]),
                    approved_tools=s.config.allowed_tools,
                    connected=s in active,
                    error=f"{type(err).__name__}: {err}" if err else None,
                )
            )
            if err:
                errors.append(f"MCP server '{s.name}' failed to start: {err}")
        if not active:
            raise NetworkAssessmentAborted(
                "No Phase-2 MCP server connected. Are nmap/modbus installed in this "
                "environment and is the agent attached to the GRFICS networks?"
            )

        # 4. run the exposure agent (evidence store in-memory, no Phase-1 data)
        store = EvidenceStore(run_id)
        for s in active:
            s.evidence = store
        limits = settings.agent.limits
        net = settings.agent.network
        agent = build_exposure_agent(
            bundle,
            mcp_servers=active,
            tools=build_network_tools(store, recorder, limits.max_tool_result_chars),
        )
        _say(
            opts,
            f"Running {agent.name} with {profile.name} (max {limits.max_turns} turns, "
            f"{limits.max_tool_calls} tool calls, {limits.max_duration_seconds:.0f}s)...",
        )
        outcome = await run_agent(
            agent,
            build_exposure_input(
                allowed_cidrs,
                allowed_hostnames,
                modbus_target,
                tool_budget=limits.max_tool_calls,
                max_turns=limits.max_turns,
            ),
            max_turns=limits.max_turns,
            timeout_seconds=limits.max_duration_seconds,
            session=open_session(run_id, settings.session_db_path),
            tracing_enabled=settings.agent.tracing_enabled,
            run_id=run_id,
            input_filter=ContextFilter(
                store,
                keep_recent=limits.keep_recent_tool_outputs,
                drop_reasoning=net.drop_old_thinking,
                show_plan=True,
            ),
            output_model=AgentAssessment,
        )
        merge_sections(outcome, list(store.sections.values()))
        outcome_status = outcome.status
        usage = outcome.usage
        if isinstance(outcome.assessment, AgentAssessment):
            assessment = outcome.assessment
        if outcome.error:
            errors.append(f"agent: {outcome.error}")
        store.close()

    # 5. metrics + report (same shape as the Phase-1 agent report)
    metrics = RunMetrics(
        started_at=started_at,
        finished_at=datetime.now(UTC),
        duration_seconds=round(time.perf_counter() - t_start, 2),
        tool_calls_total=len(recorder.records),
        tool_calls_agent=recorder.agent_calls,
        tool_calls_blocked=recorder.blocked(),
        tool_calls_by_name=recorder.counts_by_tool(),
        model_requests=usage.get("requests", 0),
        input_tokens=usage.get("input_tokens"),
        output_tokens=usage.get("output_tokens"),
        total_tokens=usage.get("total_tokens"),
    )
    report = build_agent_report(
        run_id=run_id,
        model=model_info,
        prompt_version=NET_PROMPT_VERSION,
        agent_status=outcome_status,
        snapshot_id="",  # no Docker snapshot: this agent observes the live network
        assessment=assessment,
        errors=errors,
        metrics=metrics,
    )
    md_path = write_files(
        settings.output_dir,
        run_id,
        NETWORK_REPORT,
        report.model_dump_json(indent=2),
        render_agent_markdown(report, infos),
    )
    if store.plan_versions:  # every version of the agent's own plan, for tracing
        (md_path.parent / PLAN_HISTORY).write_text(json.dumps(store.plan_versions, indent=2))
    _say(opts, f"Network assessment finished: {outcome_status}, {len(report.findings)} finding(s)")
    return NetworkResult(
        run_id=run_id,
        status=outcome_status,
        report_md_path=md_path,
        findings=len(report.findings),
    )
