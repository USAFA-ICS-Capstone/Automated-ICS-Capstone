"""Phase-2 harness tools: ``evidence_get`` and ``record_host_section``.

The live-network analogue of agents/security_tools.py. ``evidence_get`` reads
back the agent's own earlier nmap/modbus results from the shared evidence store
(reusing ``render_stored`` from the Phase-1 tools). ``record_host_section`` is
the exposure-agent counterpart of ``record_container_section``: the agent calls
it once per live host, writing findings in the SAME ``AgentFinding`` schema so
the two reports merge the same way (``merge_sections``).

All three tools (with ``update_plan``) are recorded in the tool-call audit trail
(server ``harness``) and count toward the agent's tool-call budget.
"""

from __future__ import annotations

from typing import Literal

from agents import FunctionTool, function_tool
from pydantic import BaseModel

from docker_security_agent.agents.security_tools import HARNESS_SERVER, render_stored
from docker_security_agent.mcp.evidence import EvidenceStore
from docker_security_agent.mcp.recorder import ToolCallRecorder
from docker_security_agent.mcp.shaping import to_text
from docker_security_agent.schemas.reports import AgentFinding, ContainerSection

EVIDENCE_GET = "evidence_get"
RECORD_HOST_SECTION = "record_host_section"
UPDATE_PLAN = "update_plan"


class PlanStep(BaseModel):
    """One step of the agent's own plan (Manus-style recitation).

    The harness stores and shows the plan exactly as written; it never checks
    or changes a step.
    """

    text: str
    status: Literal["todo", "doing", "done", "blocked"]


def build_network_tools(
    store: EvidenceStore,
    recorder: ToolCallRecorder,
    max_result_chars: int,
) -> list[FunctionTool]:
    """Create ``evidence_get``, ``record_host_section`` and ``update_plan`` for this run.

    ``record_host_section`` replies only "this host is done": what to do next comes
    from the agent's own plan, not from the reply. ``update_plan``: the agent writes
    and rewrites its own plan; ContextFilter shows the latest version at the end of
    every request.
    """

    @function_tool(name_override=EVIDENCE_GET)
    async def evidence_get(ref: str, select: str = "") -> str:
        """Read back a stored result of one of your earlier tool calls.

        Args:
            ref: The reference shown at the start of that result, e.g. "E7".
            select: Optional substring/field filter. Empty = the whole result.
        """
        args = {"ref": ref, "select": select}
        stored = store.get(ref)
        if stored is None:
            recorder.add(
                phase="agent",
                server=HARNESS_SERVER,
                tool=EVIDENCE_GET,
                arguments=args,
                status="error",
                error="unknown reference",
            )
            known = ", ".join(store.outputs) or "none yet"
            return f"No stored result {ref!r}. Known references: {known}."
        body = render_stored(stored, select)
        if select and not body.strip():
            body = f"Nothing in {stored.ref} matches select={select!r}."
        header = f"[{stored.ref}] {stored.tool} {stored.subject}".rstrip()
        if select:
            header += f" (select={select})"
        text = f"{header}\n" + to_text(
            body, max(max_result_chars - len(header) - 1, 1), ref=stored.ref
        )
        recorder.add(
            phase="agent",
            server=HARNESS_SERVER,
            tool=EVIDENCE_GET,
            arguments=args,
            status="ok",
            result_chars=len(text),
        )
        return text

    @function_tool(name_override=RECORD_HOST_SECTION)
    async def record_host_section(
        resource_name: str,
        findings: list[AgentFinding],
        evidence_refs: list[str],
        notes: list[str],
    ) -> str:
        """Record your finished analysis of ONE live host, right after scanning it.

        Write it while the host's scan/Modbus results are still in your context.
        Calling it again for the same host replaces the earlier section.

        Args:
            resource_name: The host - its IP, or the container/service name a scan
                revealed.
            findings: Every issue on this host, each with tool/target/result
                evidence (same format as the final assessment's findings).
            evidence_refs: References (E1, E2...) of the results you used.
            notes: Only what you could not check for this host, or a bare fact
                worth noting; [] if none.
        """
        key = resource_name.strip().lstrip("/").lower()
        again = key in store.sections
        section = ContainerSection(
            resource_name=resource_name,
            findings=findings,
            evidence_refs=evidence_refs,
            notes=notes,
        )
        store.save_section(section)
        recorder.add(
            phase="agent",
            server=HARNESS_SERVER,
            tool=RECORD_HOST_SECTION,
            arguments={
                "resource_name": resource_name,
                "findings": len(findings),
                "evidence_refs": evidence_refs,
            },
            status="ok",
        )
        if again:
            return f"Section for {resource_name} replaced. This host is done."
        return f"Section for {resource_name} recorded. This host is done."

    @function_tool(name_override=UPDATE_PLAN)
    async def update_plan(steps: list[PlanStep]) -> str:
        """Write your full current plan; it replaces your previous plan.

        Your latest plan is shown to you at the end of every turn. Rewrite it when a
        step finishes, when a step fails or cannot be done (mark it blocked), or when
        what you learn changes your plan - not after every call.

        Args:
            steps: Every step of your plan, in order. Each has `text` (short, e.g.
                "192.168.95.10: read registers, record section") and `status`:
                todo, doing, done or blocked.
        """
        if not steps:
            recorder.add(
                phase="agent",
                server=HARNESS_SERVER,
                tool=UPDATE_PLAN,
                arguments={"steps": 0},
                status="error",
                error="empty plan",
            )
            return "Plan not saved: it has no steps. Pass every step of your plan."
        version = store.save_plan([s.model_dump() for s in steps])
        recorder.add(
            phase="agent",
            server=HARNESS_SERVER,
            tool=UPDATE_PLAN,
            arguments={"steps": len(steps), "version": version},
            status="ok",
        )
        return f"Plan saved (version {version}, {len(steps)} steps)."

    return [evidence_get, record_host_section, update_plan]
