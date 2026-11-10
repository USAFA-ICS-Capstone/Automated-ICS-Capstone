"""Phase 2 (network verification) output models.

Where Phase 1 (``AgentAssessment``) is read from Docker *metadata*, Phase 2 is
read from the *wire*: for each network claim the Phase-1 agent made, the
verification agent actively tests it with nmap/modbus and records the verdict
plus the exact tool output that supports it.

This module is additive: it does not touch the Phase-1 schemas in
``schemas/reports.py``. The verification records are written incrementally by
the ``record_verification`` harness tool (the Phase-2 analogue of
``record_container_section``); the pipeline assembles them into a
``VerificationReport`` alongside the agent's own summary.

Only the VERIFY half of the task is modelled here. The later attacker-analysis
sections (asset_ranking / attack_paths / emergent_findings) are intentionally
absent until that phase is built.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from docker_security_agent.schemas.reports import ModelInfo, RunMetrics

# Keep these literals tiny: local models (prompted mode) cope badly with large
# or deeply-optional schemas, same reasoning as AgentAssessment.
Verdict = Literal["observed", "not_reproduced", "not_tested"]
AssertionType = Literal["observed", "inferred"]


class VerificationToolCall(BaseModel):
    """One MCP tool call the agent made while testing a claim (audit trail)."""

    tool: str = Field(description="Server.tool used, e.g. nmap.check_single_port or modbus.read_register")
    arguments: str = Field(description="The arguments you called it with, as a short string")
    result: str = Field(description="What the tool returned, copied/trimmed from its output")


class VerificationRecord(BaseModel):
    """The verdict on ONE Phase-1 network claim, backed by tool evidence."""

    claim: str = Field(description="The Phase-1 network claim being tested, in your own words")
    source_finding_id: str = Field(
        description="The F-AGENT-... id of the Phase-1 finding this claim came from; '' if none"
    )
    verified: Verdict = Field(
        description="observed = confirmed on the wire; not_reproduced = tool evidence "
        "contradicts it; not_tested = could not be checked"
    )
    assertion_type: AssertionType = Field(
        description="observed = you saw it directly in a tool result; inferred = you reasoned it"
    )
    evidence: str = Field(description="The exact tool output that supports this verdict")
    tool_calls: list[VerificationToolCall] = Field(
        description="Every MCP tool call you made for this claim"
    )
    notes: str = Field(description="Anything you could not confirm, or caveats; '' if none")


class VerificationAgentOutput(BaseModel):
    """The verification agent's final structured answer (the records come from
    the record_verification tool, exactly as sections do in Phase 1)."""

    executive_summary: str = Field(
        description="3-5 sentences: which Phase-1 network claims held up on the wire, which "
        "did not, and what the PLC reachability/Modbus checks showed"
    )
    limitations: list[str] = Field(description="What you could not verify; [] if none")


class VerificationReport(BaseModel):
    """Contents of verification_report.json (the .md is rendered from this)."""

    report_version: str = "1.0"
    phase: str = "network-verification"
    run_id: str  # the Phase-1 run whose claims were verified
    generated_at: datetime
    model: ModelInfo
    source_report: str  # path to the Phase-1 agent_report.json that was read
    agent_status: str  # ok / error / timeout / max_turns / invalid_output
    executive_summary: str
    verification: list[VerificationRecord]
    limitations: list[str]
    errors: list[str]
    metrics: RunMetrics
