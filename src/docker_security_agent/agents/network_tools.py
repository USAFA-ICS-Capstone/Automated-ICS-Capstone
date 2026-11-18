"""Phase-2 harness tools: ``evidence_get`` and ``record_host_section``.

The live-network analogue of agents/harness_tools.py. ``evidence_get`` reads
back the agent's own earlier nmap/modbus results from the shared evidence store
(reusing ``render_stored`` from the Phase-1 tools). ``record_host_section`` is
the exposure-agent counterpart of ``record_container_section``: the agent calls
it once per live host, writing findings in the SAME ``AgentFinding`` schema so
the two reports merge the same way (``merge_sections``).

Unlike the Phase-1 recorder there is no CVE write-time check: this agent does no
vulnerability scanning, so ``vulnerability_ids`` must always be empty. Any ids a
model puts there anyway are stripped (with a note), never saved.

Both tools are recorded in the tool-call audit trail (server ``harness``) and
count toward the agent's tool-call budget.
"""

from __future__ import annotations

from agents import FunctionTool, function_tool

from docker_security_agent.agents.harness_tools import HARNESS_SERVER, render_stored
from docker_security_agent.mcp.evidence import EvidenceStore
from docker_security_agent.mcp.recorder import ToolCallRecorder
from docker_security_agent.mcp.shaping import to_text
from docker_security_agent.schemas.reports import AgentFinding, ContainerSection

EVIDENCE_GET = "evidence_get"
RECORD_HOST_SECTION = "record_host_section"


def _strip_vuln_ids(findings: list[AgentFinding]) -> tuple[list[AgentFinding], bool]:
    """Force ``vulnerability_ids`` to [] on every finding (this agent finds none).

    Returns the cleaned findings and whether anything was stripped.
    """
    stripped = False
    cleaned: list[AgentFinding] = []
    for f in findings:
        if f.vulnerability_ids:
            stripped = True
            cleaned.append(f.model_copy(update={"vulnerability_ids": []}))
        else:
            cleaned.append(f)
    return cleaned, stripped


def host_progress(store: EvidenceStore, checklist: list[str] | None) -> str:
    """Progress line for record_host_section (mirrors harness_tools.section_progress).

    The exposure agent discovers its own hosts, so there is usually no fixed
    checklist: it simply moves to the next live host. When a checklist of
    expected hosts is supplied, the reply names which still lack a section.
    """
    if not checklist:
        return (
            "Continue with the next live host; when every live host you found has a "
            "section, produce the final assessment."
        )
    done = {name.strip().lstrip("/").lower() for name in store.sections}
    remaining = [h for h in checklist if h.strip().lstrip("/").lower() not in done]
    covered = len(checklist) - len(remaining)
    if remaining:
        shown = ", ".join(remaining[:10]) + (" ..." if len(remaining) > 10 else "")
        return (
            f"Hosts with a section: {covered} of {len(checklist)}. Still to do: {shown}. "
            "Continue with the next one."
        )
    return (
        f"All {len(checklist)} expected hosts now have a section. Do not record them again. "
        "Check for cross-host / segmentation issues, then produce the final assessment."
    )


def build_network_tools(
    store: EvidenceStore,
    recorder: ToolCallRecorder,
    max_result_chars: int,
    checklist: list[str] | None = None,
) -> list[FunctionTool]:
    """Create ``evidence_get`` + ``record_host_section`` bound to this run.

    ``checklist``: optional list of hosts the agent is expected to cover; when
    omitted (the usual case) the agent self-paces over the hosts it discovers.
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
                vulnerability_ids must be [] (this run does no vuln scanning).
            evidence_refs: References (E1, E2...) of the results you used.
            notes: Only what you could not check for this host, or a bare fact
                worth noting; [] if none.
        """
        cleaned, stripped = _strip_vuln_ids(findings)
        if stripped:
            notes = [
                *notes,
                "vulnerability_ids were cleared: this run assesses live exposure, not "
                "image vulnerabilities.",
            ]
        key = resource_name.strip().lstrip("/").lower()
        again = key in store.sections
        section = ContainerSection(
            resource_name=resource_name,
            findings=cleaned,
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
                "findings": len(cleaned),
                "evidence_refs": evidence_refs,
            },
            status="ok",
        )
        head = (
            f"Section for {resource_name} replaced: it already had one."
            if again
            else f"Section for {resource_name} recorded ({len(cleaned)} findings)."
        )
        return (
            f"{head} Its tool results may now be shortened in your context; they stay "
            f"available with evidence_get. {host_progress(store, checklist)}"
        )

    return [evidence_get, record_host_section]
