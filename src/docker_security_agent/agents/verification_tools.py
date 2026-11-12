"""Phase-2 harness tools: ``evidence_get`` and ``record_verification``.

The Phase-2 analogue of agents/harness_tools.py. ``evidence_get`` reads back the
agent's own earlier nmap/modbus results from the shared evidence store (reusing
``render_stored`` from the Phase-1 tools). ``record_verification`` is the verify
counterpart of ``record_container_section``: the agent calls it once per claim,
and the records accumulate in a ``VerificationCollector`` that survives even if
the agent later times out, so a partial run still yields a report.

Both are recorded in the tool-call audit trail (server ``harness``) and count
toward the tool-call budget.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from agents import FunctionTool, function_tool

from docker_security_agent.agents.harness_tools import HARNESS_SERVER, render_stored
from docker_security_agent.mcp.evidence import EvidenceStore
from docker_security_agent.mcp.recorder import ToolCallRecorder
from docker_security_agent.mcp.shaping import to_text
from docker_security_agent.schemas.verification import (
    VerificationRecord,
    VerificationToolCall,
)

EVIDENCE_GET = "evidence_get"
RECORD_VERIFICATION = "record_verification"

_FINDING_ID_RE = re.compile(r"F-AGENT-[0-9a-f]+", re.IGNORECASE)

# h6: how many record_verification calls may pass without the set of still-unverified
# claims shrinking before the tool forces the agent to wrap up. Keeps a few claims the
# model cannot crack (e.g. a CVE it has no tool for) from jamming the all-or-nothing
# exit gate and burning the whole turn budget on re-recording covered claims.
_STALL_LIMIT = 8


@dataclass
class VerificationCollector:
    """Holds the verification records as the agent writes them (one per claim).

    Keyed by the claim text so a re-recorded claim replaces the earlier verdict,
    mirroring how record_container_section replaces a container's section.
    """

    records: dict[str, VerificationRecord] = field(default_factory=dict)

    def add(self, record: VerificationRecord) -> bool:
        key = record.claim.strip().lower()
        existed = key in self.records
        self.records[key] = record
        return existed

    def as_list(self) -> list[VerificationRecord]:
        return list(self.records.values())

    def covered_ids(self) -> set[str]:
        """Phase-1 finding ids that already have a verdict (by source_finding_id
        or an id mentioned in the claim text)."""
        ids: set[str] = set()
        for r in self.records.values():
            if r.source_finding_id.strip():
                ids.add(r.source_finding_id.strip().upper())
            ids.update(m.upper() for m in _FINDING_ID_RE.findall(r.claim))
        return ids


def verification_progress(collector: VerificationCollector, checklist: list[str]) -> str:
    """What record_verification answers (mirrors harness_tools.section_progress).

    Tells the agent how many Phase-1 claims still need a verdict and, after the
    last one, to produce ONLY the final summary (the verdicts are added to the
    report automatically from the records it already wrote).
    """
    want = [c.strip().upper() for c in checklist]
    covered = collector.covered_ids()
    remaining = [c for c in want if c not in covered]
    done = len(want) - len(remaining)
    if remaining:
        shown = ", ".join(remaining[:8]) + (" ..." if len(remaining) > 8 else "")
        return (
            f"Claims with a verdict: {done} of {len(want)}. Still to verify: {shown}. "
            "Test the next one, then call record_verification for it."
        )
    return (
        f"All {len(want)} Phase-1 network claims now have a verdict. Do not record them "
        "again. Produce your final answer NOW, and make it ONLY the executive_summary and "
        "limitations — do NOT include the verdicts, they are added to the report "
        "automatically from your record_verification calls."
    )


def build_verification_tools(
    store: EvidenceStore,
    recorder: ToolCallRecorder,
    collector: VerificationCollector,
    max_result_chars: int,
    checklist: list[str] | None = None,
) -> list[FunctionTool]:
    """Create ``evidence_get`` + ``record_verification`` bound to this run.

    ``checklist``: the Phase-1 finding ids the agent has to work through; the
    record tool's reply says which still lack a verdict (h5-style progress).
    """

    # h6 stall state: the last set of still-unverified ids and how many record
    # calls in a row have left it unchanged. Shared across record_verification calls.
    stall: dict[str, object] = {"sig": None, "n": 0}

    @function_tool(name_override=EVIDENCE_GET)
    async def evidence_get(ref: str, select: str = "") -> str:
        """Read back a stored result of one of your earlier tool calls.

        Args:
            ref: The reference shown at the start of that result, e.g. "E3".
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

    @function_tool(name_override=RECORD_VERIFICATION)
    async def record_verification(
        claim: str,
        source_finding_id: str,
        verified: str,
        assertion_type: str,
        evidence: str,
        tool_calls: list[VerificationToolCall],
        notes: str,
    ) -> str:
        """Record your verdict on ONE Phase-1 network claim, right after testing it.

        Args:
            claim: The Phase-1 claim you tested, in your own words.
            source_finding_id: The F-AGENT-... id it came from, or "".
            verified: "observed" | "not_reproduced" | "not_tested".
            assertion_type: "observed" (seen in a tool result) | "inferred".
            evidence: The exact tool output supporting your verdict.
            tool_calls: Every MCP tool call you made for this claim.
            notes: Caveats / what you could not confirm; "" if none.
        """
        record = VerificationRecord(
            claim=claim,
            source_finding_id=source_finding_id,
            verified=verified,  # type: ignore[arg-type]
            assertion_type=assertion_type,  # type: ignore[arg-type]
            evidence=evidence,
            tool_calls=tool_calls,
            notes=notes,
        )
        again = collector.add(record)
        recorder.add(
            phase="agent",
            server=HARNESS_SERVER,
            tool=RECORD_VERIFICATION,
            arguments={
                "claim": claim[:200],
                "verified": verified,
                "tool_calls": len(tool_calls),
            },
            status="ok",
        )
        head = (
            f"Verdict for this claim replaced (verified={verified})."
            if again
            else f"Recorded (verified={verified})."
        )
        if checklist is None:
            return (
                f"{head} Continue with the next claim; when every claim has a verdict, "
                "produce ONLY your executive_summary and limitations as the final answer "
                "(the verdicts are added to the report automatically)."
            )

        # Progress + stall detection (h6). Recompute the remaining set so we can tell
        # whether this call actually moved the needle.
        want = [c.strip().upper() for c in checklist]
        remaining = [c for c in want if c not in collector.covered_ids()]
        sig = tuple(remaining)
        if sig == stall["sig"]:
            stall["n"] = int(stall["n"]) + 1  # type: ignore[arg-type]
        else:
            stall["sig"] = sig
            stall["n"] = 0

        if not remaining:
            return f"{head} {verification_progress(collector, checklist)}"

        # Fix 1: re-recording a claim that already has a verdict is a dead end. Say so
        # plainly so the model stops looping on covered claims (mirrors Phase 1's
        # "do not record them again").
        dead_end = (
            "You already recorded this claim — do NOT record it again. " if again else ""
        )

        # Fix 2: escape hatch. If the same claims have stayed unverified for too many
        # record calls, the model cannot crack them; tell it to stop and wrap up. Any
        # claim still without a verdict is filled in as not_tested by the pipeline.
        if int(stall["n"]) >= _STALL_LIMIT:  # type: ignore[arg-type]
            shown = ", ".join(remaining[:8]) + (" ..." if len(remaining) > 8 else "")
            return (
                f"{head} {dead_end}You have tried enough — the remaining claim(s) ({shown}) "
                "cannot be verified with nmap/modbus. Do NOT record anything else. Produce "
                "your final answer NOW: ONLY the executive_summary and limitations. Any claim "
                "still without a verdict is recorded as not_tested automatically."
            )
        return f"{head} {dead_end}{verification_progress(collector, checklist)}"

    return [evidence_get, record_verification]
