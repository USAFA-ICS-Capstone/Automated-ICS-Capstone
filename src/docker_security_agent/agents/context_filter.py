"""Context management before every model call (harness h2, h7).

``RunConfig.call_model_input_filter`` runs immediately before each model
request and may change what is sent, not what is stored: the session still
holds every item in full. ``ContextFilter``:

* keeps the most recent ``keep_recent`` tool results in full;
* replaces each older one with a one-line stub that names its reference, so
  the agent can fetch it back with ``evidence_get``, and, when the agent has
  already written that container's section, says so;
* never shortens the harness tools' own results (``evidence_get`` output is
  what the agent fetched on purpose: shortening it would make it fetch again).

Two optional steps (h7, off by default, used by the Phase-2 network agent):

* ``drop_reasoning``: leave the model's earlier thinking (``type: reasoning``
  items) out of the request. With vLLM/Qwen the SDK otherwise re-sends every
  earlier thinking block, and a model that sees its own identical reasoning
  several times tends to copy it again (run net-20261118-171115-f80b: 17
  blocks, byte-identical from turn 7 on, ~77% of the prompt).
* ``show_plan``: attach the agent's latest ``update_plan`` plan, exactly as
  written, to the end of the newest tool result, so it is the last thing the
  model reads (Manus-style recitation). It is added to the request only, never
  stored, so there is always exactly one copy. Earlier ``update_plan`` calls
  stay in the history unchanged.

Correlation is by the reference at the start of each result (``[E7] ...``,
written by GuardedMCPServer), plus ``call_id`` to identify the tool, so the
stub always replaces the result it describes.

The filter is a pure function of its input: it stores nothing, its stubs start
with the same reference, and an attached plan is replaced (not added again)
when one is already there, so applying it again gives the same result.
The SDK's built-in ``ToolOutputTrimmer`` is not used because it keeps a
character preview instead of a reference to the full result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from agents.run_config import CallModelData, ModelInputData

from docker_security_agent.agents.network_tools import RECORD_HOST_SECTION, UPDATE_PLAN
from docker_security_agent.agents.security_tools import EVIDENCE_GET, RECORD_SECTION
from docker_security_agent.mcp.evidence import EvidenceStore

PROTECTED_TOOLS = frozenset({EVIDENCE_GET, RECORD_SECTION, RECORD_HOST_SECTION, UPDATE_PLAN})
STUB_MARKER = "full result removed from context"
PLAN_MARKER = "=== YOUR PLAN"
_REF_RE = re.compile(r"^\[(E\d+)\]")


def _output_text(output: Any) -> str:
    if isinstance(output, str):
        return output
    if isinstance(output, list):
        return "".join(str(part.get("text", "")) for part in output if isinstance(part, dict))
    return ""


def _with_text(item: dict[str, Any], text: str) -> dict[str, Any]:
    """A copy of a function_call_output item whose output is ``text``, same shape."""
    item = dict(item)
    if isinstance(item.get("output"), list):
        item["output"] = [{"type": "input_text", "text": text}]
    else:
        item["output"] = text
    return item


def stub_text(store: EvidenceStore, ref: str) -> str:
    stored = store.get(ref)
    if stored is None:
        return f'[{ref}] {STUB_MARKER}. Fetch it with evidence_get("{ref}").'
    what = f"{stored.tool} {stored.subject}".rstrip()
    section = store.section_for(stored)
    written = f" Your section for {section} is already recorded." if section else ""
    return (
        f"[{ref}] {what}: {STUB_MARKER} to save space.{written} "
        f'Fetch it with evidence_get("{ref}") (select=... for one part).'
    )


def plan_text(store: EvidenceStore) -> str:
    """The latest plan, exactly as the agent wrote it (text and status unchanged)."""
    steps = store.plan or []
    version = len(store.plan_versions)
    lines = [
        f"{PLAN_MARKER} (latest: version {version}, written by you with update_plan) ===",
        *(f"{i}. [{s.get('status', '')}] {s.get('text', '')}" for i, s in enumerate(steps, 1)),
        "Rewrite it with update_plan when a step finishes, fails or cannot be done, "
        "or when what you learn changes your plan.",
    ]
    return "\n".join(lines)


@dataclass
class ContextFilter:
    store: EvidenceStore
    keep_recent: int = 8
    drop_reasoning: bool = False
    show_plan: bool = False

    def __call__(self, data: CallModelData[Any]) -> ModelInputData:
        items = list(data.model_data.input)
        changed = False

        if self.drop_reasoning:
            kept = [
                it for it in items if not (isinstance(it, dict) and it.get("type") == "reasoning")
            ]
            changed = len(kept) != len(items)
            items = kept

        tool_of = {
            it.get("call_id"): it.get("name")
            for it in items
            if isinstance(it, dict) and it.get("type") == "function_call"
        }
        candidates: list[tuple[int, str]] = []
        outputs: list[int] = []
        for i, it in enumerate(items):
            if not (isinstance(it, dict) and it.get("type") == "function_call_output"):
                continue
            outputs.append(i)
            if tool_of.get(it.get("call_id")) in PROTECTED_TOOLS:
                continue
            match = _REF_RE.match(_output_text(it.get("output")))
            if match:
                candidates.append((i, match.group(1)))

        old = candidates[: max(len(candidates) - self.keep_recent, 0)]
        for i, ref in old:
            items[i] = _with_text(items[i], stub_text(self.store, ref))
            changed = True

        if self.show_plan and self.store.plan and outputs:
            last = outputs[-1]
            text = _output_text(items[last].get("output"))
            if PLAN_MARKER in text:  # already attached (filter applied twice)
                text = text[: text.index(PLAN_MARKER)].rstrip("\n")
            items[last] = _with_text(items[last], f"{text}\n\n{plan_text(self.store)}")
            changed = True

        if not changed:
            return data.model_data
        return ModelInputData(input=items, instructions=data.model_data.instructions)
