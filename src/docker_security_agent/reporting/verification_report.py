"""The Phase-2 verification report: ``verification_report.json`` + ``.md``.

What the verification agent confirmed or refuted on the wire, each verdict kept
next to the live tool evidence and the MCP tool calls that produced it, so the
active checks stay auditable. Independent of the Phase-1 agent report it was
built from (that report is only read, never changed).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from docker_security_agent.reporting.generator import (
    _md_escape,
    metrics_markdown,
    write_files,
)
from docker_security_agent.schemas.reports import MCPServerInfo, ModelInfo, RunMetrics
from docker_security_agent.schemas.verification import (
    VerificationAgentOutput,
    VerificationRecord,
    VerificationReport,
)

VERIFICATION_REPORT = "verification_report"

_VERDICT_ICON = {"observed": "🟢", "not_reproduced": "🔴", "not_tested": "⚪"}


def build_verification_report(
    *,
    run_id: str,
    model: ModelInfo,
    source_report: str,
    agent_status: str,
    output: VerificationAgentOutput | None,
    records: list[VerificationRecord],
    errors: list[str],
    metrics: RunMetrics,
) -> VerificationReport:
    summary = (
        output.executive_summary
        if output is not None
        else f"The verification agent produced no valid summary (status: {agent_status})."
    )
    limitations = list(output.limitations) if output is not None else []
    return VerificationReport(
        run_id=run_id,
        generated_at=datetime.now(UTC),
        model=model,
        source_report=source_report,
        agent_status=agent_status,
        executive_summary=summary,
        verification=records,
        limitations=limitations,
        errors=list(errors),
        metrics=metrics,
    )


def _record_block(r: VerificationRecord) -> str:
    icon = _VERDICT_ICON.get(r.verified, "•")
    md = [f"#### {icon} {_md_escape(r.claim)}\n"]
    src = f" · from `{r.source_finding_id}`" if r.source_finding_id.strip() else ""
    md.append(
        f"- **Verdict:** `{r.verified}` · **Assertion:** {r.assertion_type}{src}\n"
    )
    md.append(f"- **Evidence:** {_md_escape(r.evidence) or '_none_'}\n")
    if r.tool_calls:
        md.append("- **Tool calls:**")
        for tc in r.tool_calls:
            md.append(
                f"  - `{_md_escape(tc.tool)}({_md_escape(tc.arguments)})` → "
                f"{_md_escape(tc.result)}"
            )
    if r.notes.strip():
        md.append(f"- **Notes:** {_md_escape(r.notes)}")
    return "\n".join(md) + "\n"


def render_verification_markdown(r: VerificationReport, mcp_servers: list[MCPServerInfo]) -> str:
    md: list[str] = []
    md.append(f"# Phase 2 — Network Verification — `{r.run_id}`\n")
    md.append(
        f"**Agent status:** {r.agent_status} · **Generated:** "
        f"{r.generated_at:%Y-%m-%d %H:%M UTC}\n"
    )
    md.append(
        f"**Model:** `{r.model.profile}` ({r.model.provider} / `{r.model.model}`) · "
        f"**Verified from:** `{r.source_report}`\n"
    )
    md.append(
        "> Each Phase-1 network claim tested on the wire with nmap/modbus. Verdicts: "
        "🟢 observed (confirmed), 🔴 not_reproduced (contradicted), ⚪ not_tested. Every "
        "assertion is tagged observed/inferred and every MCP tool call is logged.\n"
    )

    counts = {"observed": 0, "not_reproduced": 0, "not_tested": 0}
    for rec in r.verification:
        counts[rec.verified] = counts.get(rec.verified, 0) + 1

    md.append("## 1. Summary\n")
    md.append(f"{r.executive_summary}\n")
    md.append(
        f"Claims verified: {len(r.verification)} "
        f"(🟢 observed {counts['observed']}, 🔴 not_reproduced {counts['not_reproduced']}, "
        f"⚪ not_tested {counts['not_tested']})\n"
    )

    md.append("\n## 2. Verification\n")
    if r.verification:
        for rec in r.verification:
            md.append(_record_block(rec))
    else:
        md.append("_No claims were recorded._\n")

    md.append("\n## 3. Limitations (stated by the agent)\n")
    md.append(
        "\n".join(f"- {lim}" for lim in r.limitations) + "\n" if r.limitations else "_None._\n"
    )
    if r.errors:
        md.append("\n**Errors / notes during the run:**\n")
        md.append("\n".join(f"- {_md_escape(n)}" for n in r.errors) + "\n")

    md.append("\n## 4. Execution metrics\n")
    md.append(metrics_markdown(r.metrics, mcp_servers))
    return "\n".join(md)


def write_verification_report(
    report: VerificationReport, mcp_servers: list[MCPServerInfo], output_dir: Path
) -> Path:
    """Write the verification report (.json + .md); return the .md path."""
    return write_files(
        output_dir,
        report.run_id,
        VERIFICATION_REPORT,
        report.model_dump_json(indent=2),
        render_verification_markdown(report, mcp_servers),
    )
