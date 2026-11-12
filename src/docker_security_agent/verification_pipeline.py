"""Phase 2 (network verification) run, end to end.

``run_verification`` is what ``docker-audit verify`` calls. It is deliberately
SEPARATE from pipeline.py: it does not touch the Phase-1 assessment flow. It

    1. finds a finished Phase-1 run and READS its agent_report.json,
    2. pulls the network-relevant claims out of it,
    3. connects the Phase-2 MCP servers (nmap + modbus) from the SAME config
       and GuardedMCPServer machinery Phase 1 uses,
    4. runs NetworkVerificationAgent (reusing security_assessment.run_agent) to
       confirm/refute each claim on the wire,
    5. writes outputs/<run_id>/verification_report.{json,md}.

Vantage point (Option A): the nmap/modbus servers run as stdio subprocesses
inside the agent container, which `verify` is run with attached to the GRFICS
ICS/DMZ networks (deploy/agent/compose.grfics.example.yml). That gives them the
Kali network position without running anything inside the kali container.
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
from docker_security_agent.agents.network_verification import (
    build_verify_agent,
    build_verify_input,
)
from docker_security_agent.agents.security_assessment import run_agent
from docker_security_agent.agents.verification_tools import (
    _FINDING_ID_RE,
    VerificationCollector,
    build_verification_tools,
)
from docker_security_agent.config import ConfigError, Settings
from docker_security_agent.llm.capabilities import check_profile
from docker_security_agent.llm.factory import build_model
from docker_security_agent.mcp.evidence import EvidenceStore
from docker_security_agent.mcp.policy import ToolPolicy
from docker_security_agent.mcp.recorder import ToolCallRecorder
from docker_security_agent.mcp.registry import build_servers, connect
from docker_security_agent.mcp.servers import GuardedMCPServer
from docker_security_agent.memory.sessions import open_session
from docker_security_agent.reporting.verification_report import (
    build_verification_report,
    write_verification_report,
)
from docker_security_agent.schemas.reports import MCPServerInfo, ModelInfo, RunMetrics
from docker_security_agent.schemas.verification import (
    VerificationAgentOutput,
    VerificationRecord,
)

PHASE2_ROLES = {"network_scanner", "ics_protocol"}

# A finding is "network-relevant" if any of these appear in its title,
# explanation or an evidence field path/value.
_NET_KEYWORDS = (
    "network",
    "port",
    "modbus",
    "502",
    "reach",
    "expos",
    "cap_net",
    "net_admin",
    "net_raw",
    "vnc",
    "dmz",
    "ics-net",
    "published",
    "listen",
)


class VerificationAborted(Exception):
    """The verify run cannot proceed (no source report, servers down, etc.)."""


@dataclass
class VerifyOptions:
    model_profile: str | None = None
    run_id: str | None = None  # None -> the latest run that has an agent_report.json
    skip_model_check: bool = False
    objective: str | None = None
    progress: Callable[[str], None] | None = None
    notes: list[str] = field(default_factory=list)


@dataclass
class VerifyResult:
    run_id: str
    status: str
    source_report: Path
    report_md_path: Path
    records: int


def _say(opts: VerifyOptions, message: str) -> None:
    if opts.progress:
        opts.progress(message)


# ---------------------------------------------------------------------------
# Reading the Phase-1 report and extracting claims
# ---------------------------------------------------------------------------


def find_source_report(output_dir: Path, run_id: str | None) -> tuple[str, Path]:
    """Return (run_id, path to agent_report.json) for the chosen or latest run."""
    if run_id:
        path = output_dir / run_id / "agent_report.json"
        if not path.exists():
            raise VerificationAborted(f"No agent_report.json for run '{run_id}' in {output_dir}.")
        return run_id, path
    candidates = sorted(
        (p for p in output_dir.glob("run-*/agent_report.json")),
        key=lambda p: p.parent.name,
        reverse=True,
    )
    if not candidates:
        raise VerificationAborted(
            f"No Phase-1 agent_report.json found under {output_dir}. Run `docker-audit assess` "
            "first, or pass --run."
        )
    return candidates[0].parent.name, candidates[0]


def _finding_is_network(finding: dict) -> bool:
    haystack = " ".join(
        [
            str(finding.get("title", "")),
            str(finding.get("explanation", "")),
            " ".join(
                f"{e.get('path', '')} {e.get('value', '')}"
                for e in finding.get("evidence", [])
                if isinstance(e, dict)
            ),
        ]
    ).lower()
    return any(k in haystack for k in _NET_KEYWORDS)


def fill_missing_as_not_tested(
    collector: VerificationCollector, claim_by_id: dict[str, str]
) -> list[str]:
    """h6 escape hatch: give every checklist claim the agent never reached a
    ``not_tested`` verdict, so the report always covers the full checklist even when
    the agent runs out of turns. Returns the ids that were filled in. These are
    flagged in their notes so they are never read as a tested-and-negative result.
    """
    covered = collector.covered_ids()
    missed = [fid for fid in claim_by_id if fid.upper() not in covered]
    for fid in missed:
        collector.add(
            VerificationRecord(
                claim=claim_by_id[fid],
                source_finding_id=fid,
                verified="not_tested",
                assertion_type="inferred",
                evidence="",
                tool_calls=[],
                notes="Agent did not reach this claim before finishing.",
            )
        )
    return missed


def network_claims(report_json: dict) -> list[str]:
    """Human-readable claim strings for the network-relevant Phase-1 findings."""
    claims: list[str] = []
    for f in report_json.get("findings", []):
        if not isinstance(f, dict) or not _finding_is_network(f):
            continue
        ev = "; ".join(
            f"{e.get('path', '')}={e.get('value', '')}"
            for e in f.get("evidence", [])
            if isinstance(e, dict)
        )
        fid = f.get("id", "")
        claim = f"[{fid}] {f.get('title', '?')} on '{f.get('resource_name', '?')}'"
        if ev:
            claim += f" (Phase-1 evidence: {ev})"
        claims.append(claim)
    return claims


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def run_verification(settings: Settings, opts: VerifyOptions) -> VerifyResult:
    set_tracing_disabled(not settings.agent.tracing_enabled)

    # 0. source report + claims
    source_run_id, source_path = find_source_report(settings.output_dir, opts.run_id)
    report_json = json.loads(source_path.read_text())
    claims = network_claims(report_json)
    _say(opts, f"Verifying run {source_run_id}: {len(claims)} network claim(s) from {source_path}")

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
        raise VerificationAborted(
            "No Phase-2 servers are enabled (need roles network_scanner + ics_protocol in "
            "config/mcp_servers.yaml)."
        )
    _say(opts, "Starting Phase-2 MCP servers: " + ", ".join(s.name for s in servers))

    errors = list(opts.notes)
    collector = VerificationCollector()
    output: VerificationAgentOutput | None = None
    outcome_status = "error"
    outcome_error: str | None = None
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
            raise VerificationAborted(
                "No Phase-2 MCP server connected. Are nmap/modbus installed in this "
                "environment and is the agent attached to the GRFICS networks?"
            )

        # 3. run the verification agent (evidence store in-memory; isolated from
        #    the Phase-1 assessment database on purpose)
        store = EvidenceStore(source_run_id)
        for s in active:
            s.evidence = store
        limits = settings.agent.limits
        # h5-style checklist: the Phase-1 finding ids the agent must give a verdict
        # on. record_verification's reply reports which still remain.
        checklist = _FINDING_ID_RE.findall(" ".join(claims))
        # id -> its claim text, so a claim the agent never reaches can be filled in
        # as not_tested after the run (h6 escape hatch, below).
        claim_by_id: dict[str, str] = {}
        for c in claims:
            m = _FINDING_ID_RE.search(c)
            if m:
                claim_by_id.setdefault(m.group(0).upper(), c)
        agent = build_verify_agent(
            bundle,
            mcp_servers=active,
            tools=build_verification_tools(
                store, recorder, collector, limits.max_tool_result_chars, checklist=checklist
            ),
        )
        _say(
            opts,
            f"Running {agent.name} with {profile.name} (max {limits.max_turns} turns, "
            f"{limits.max_tool_calls} tool calls, {limits.max_duration_seconds:.0f}s)...",
        )
        outcome = await run_agent(
            agent,
            build_verify_input(claims),
            max_turns=limits.max_turns,
            timeout_seconds=limits.max_duration_seconds,
            # Fresh session each run (unique suffix) so a re-verify never replays a
            # previous run's tool results and "summarises from memory" without testing.
            session=open_session(
                f"{source_run_id}-verify-{secrets.token_hex(3)}", settings.session_db_path
            ),
            tracing_enabled=settings.agent.tracing_enabled,
            run_id=f"{source_run_id}-verify",
            input_filter=ContextFilter(store, keep_recent=limits.keep_recent_tool_outputs),
            output_model=VerificationAgentOutput,
        )
        outcome_status = outcome.status
        outcome_error = outcome.error
        usage = outcome.usage
        if isinstance(outcome.assessment, VerificationAgentOutput):
            output = outcome.assessment
        if outcome_error:
            errors.append(f"agent: {outcome_error}")

    # 3b. h6 escape hatch: any Phase-1 claim the agent never gave a verdict on is
    # recorded as not_tested, so the report always covers the full checklist even if
    # the agent ran out of turns on a few stubborn claims.
    missed = fill_missing_as_not_tested(collector, claim_by_id)
    if missed:
        errors.append(
            f"{len(missed)} claim(s) the agent did not reach were recorded as not_tested."
        )

    # 4. metrics + report
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
    report = build_verification_report(
        run_id=source_run_id,
        model=model_info,
        source_report=str(source_path),
        agent_status=outcome_status,
        output=output,
        records=collector.as_list(),
        errors=errors,
        metrics=metrics,
    )
    md_path = write_verification_report(report, infos, settings.output_dir)
    _say(
        opts,
        f"Verification finished: {outcome_status}, {len(collector.records)} claim(s) recorded",
    )
    return VerifyResult(
        run_id=source_run_id,
        status=outcome_status,
        source_report=source_path,
        report_md_path=md_path,
        records=len(collector.records),
    )
