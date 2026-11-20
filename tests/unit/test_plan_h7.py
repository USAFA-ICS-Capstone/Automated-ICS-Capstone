"""Harness h7: the agent's own plan (update_plan) and dropping old thinking."""

import copy
import json

from agents.run_config import CallModelData, ModelInputData
from agents.tool_context import ToolContext

from docker_security_agent.agents.context_filter import PLAN_MARKER, ContextFilter
from docker_security_agent.agents.network_assessment import (
    NET_PROMPT_VERSION,
    PLAN_SECTION,
    build_exposure_agent,
)
from docker_security_agent.agents.network_tools import UPDATE_PLAN, build_network_tools
from docker_security_agent.config import AgentConfig
from docker_security_agent.mcp.evidence import EvidenceStore
from docker_security_agent.mcp.recorder import ToolCallRecorder

PLAN_V1 = [
    {"text": "sweep both subnets", "status": "done"},
    {"text": "192.168.95.10: read registers, record section", "status": "doing"},
    {"text": "final assessment", "status": "todo"},
]


async def _update_plan(store, recorder, steps):
    tools = {t.name: t for t in build_network_tools(store, recorder, 4000)}
    tool = tools[UPDATE_PLAN]
    args = json.dumps({"steps": steps})
    ctx = ToolContext(context=None, tool_name=tool.name, tool_call_id="p", tool_arguments=args)
    return await tool.on_invoke_tool(ctx, args)


def _apply(flt, items):
    data = CallModelData(
        model_data=ModelInputData(input=items, instructions="i"), agent=None, context=None
    )
    return flt(data).input


def _text(item):
    out = item["output"]
    return out if isinstance(out, str) else out[0]["text"]


def _turn(n, *, ref=None, tool="nmap_scan", text=None, list_output=False):
    """One model turn as the session stores it: thinking, tool call, tool result."""
    body = text if text is not None else f"[{ref or f'E{n}'}] {tool}\nresult {n}"
    output = [{"type": "input_text", "text": body}] if list_output else body
    return [
        {
            "type": "reasoning",
            "id": "__fake_id__",
            "summary": [],
            "content": [{"type": "reasoning_text", "text": f"thinking for turn {n}"}],
        },
        {"type": "function_call", "call_id": f"c{n}", "name": tool, "arguments": "{}"},
        {"type": "function_call_output", "call_id": f"c{n}", "output": output},
    ]


def _history(turns, **kw):
    items = [{"role": "user", "content": "OBJECTIVE: ..."}]
    for n in range(1, turns + 1):
        items += _turn(n, **kw)
    return items


def _outputs(items):
    return [it for it in items if it.get("type") == "function_call_output"]


# ---------------------------------------------------------------------------
# update_plan + store
# ---------------------------------------------------------------------------


async def test_update_plan_saves_latest_and_keeps_every_version():
    store, recorder = EvidenceStore("t"), ToolCallRecorder(20)
    reply = await _update_plan(store, recorder, PLAN_V1)
    assert reply == "Plan saved (version 1, 3 steps)."
    v2 = [dict(PLAN_V1[0]), {"text": "192.168.95.10", "status": "done"}, dict(PLAN_V1[2])]
    reply = await _update_plan(store, recorder, v2)
    assert reply == "Plan saved (version 2, 3 steps)."
    assert store.plan == v2  # only the latest is "the plan"
    assert [v["version"] for v in store.plan_versions] == [1, 2]
    assert store.plan_versions[0]["steps"] == PLAN_V1
    assert recorder.counts_by_tool()[f"harness.{UPDATE_PLAN}"] == 2  # audit trail + budget


async def test_update_plan_is_stored_as_written_not_checked():
    """The harness never judges the plan: an unproven 'done' is saved as-is."""
    store, recorder = EvidenceStore("t"), ToolCallRecorder(20)
    steps = [{"text": ".11: registers read (E99)", "status": "done"}]
    await _update_plan(store, recorder, steps)
    assert store.plan == steps


async def test_update_plan_rejects_an_empty_plan():
    store, recorder = EvidenceStore("t"), ToolCallRecorder(20)
    reply = await _update_plan(store, recorder, [])
    assert "not saved" in reply
    assert store.plan is None and store.plan_versions == []


def test_update_plan_is_always_offered():
    store, recorder = EvidenceStore("t"), ToolCallRecorder(20)
    names = {t.name for t in build_network_tools(store, recorder, 4000)}
    assert names == {"evidence_get", "record_host_section", UPDATE_PLAN}


# ---------------------------------------------------------------------------
# ContextFilter: drop old thinking
# ---------------------------------------------------------------------------


def test_drop_reasoning_removes_only_thinking_and_keeps_history_intact():
    store = EvidenceStore("t")
    items = _history(3)
    before = copy.deepcopy(items)
    out = _apply(ContextFilter(store, drop_reasoning=True), items)
    assert items == before  # the stored history is not touched
    assert not [it for it in out if it.get("type") == "reasoning"]
    assert out == [it for it in items if it.get("type") != "reasoning"]  # calls/results kept


def test_thinking_is_kept_by_default():
    store = EvidenceStore("t")
    items = _history(3)
    assert _apply(ContextFilter(store), items) == items  # unchanged = previous behaviour


# ---------------------------------------------------------------------------
# ContextFilter: show the latest plan at the end
# ---------------------------------------------------------------------------


def test_plan_is_attached_once_to_the_newest_tool_result():
    store = EvidenceStore("t")
    store.save_plan(PLAN_V1)
    items = _history(3)
    out = _outputs(_apply(ContextFilter(store, show_plan=True), items))
    assert [PLAN_MARKER in _text(o) for o in out] == [False, False, True]
    last = _text(out[-1])
    assert last.startswith("[E3] nmap_scan\nresult 3\n\n" + PLAN_MARKER)
    assert "version 1" in last
    assert "1. [done] sweep both subnets" in last  # exactly as the model wrote it
    assert "2. [doing] 192.168.95.10: read registers, record section" in last
    assert "3. [todo] final assessment" in last


def test_plan_keeps_the_output_shape():
    store = EvidenceStore("t")
    store.save_plan(PLAN_V1)
    out = _outputs(_apply(ContextFilter(store, show_plan=True), _history(2, list_output=True)))
    assert isinstance(out[-1]["output"], list) and PLAN_MARKER in _text(out[-1])


def test_plan_does_not_build_up_over_turns():
    """The copy is added to the request only, so the session never accumulates copies."""
    store = EvidenceStore("t")
    store.save_plan(PLAN_V1)
    flt = ContextFilter(store, drop_reasoning=True, show_plan=True)
    session = _history(1)
    for n in range(2, 5):  # three more turns
        sent = _apply(flt, session)
        assert sum(PLAN_MARKER in _text(o) for o in _outputs(sent)) == 1
        assert not any(PLAN_MARKER in _text(o) for o in _outputs(session))  # never stored
        session = session + _turn(n)


def test_old_update_plan_calls_are_left_unchanged_and_latest_is_shown():
    store = EvidenceStore("t")
    items = _history(1)
    store.save_plan(PLAN_V1)
    items += _turn(2, tool=UPDATE_PLAN, text="Plan saved (version 1, 3 steps).")
    items[-2]["arguments"] = json.dumps({"steps": PLAN_V1})
    v2 = [{"text": "everything", "status": "done"}]
    store.save_plan(v2)
    items += _turn(3, tool=UPDATE_PLAN, text="Plan saved (version 2, 1 steps).")
    items += _turn(4)
    before = copy.deepcopy(items)
    out = _apply(ContextFilter(store, show_plan=True), items)
    calls = [it for it in out if it.get("name") == UPDATE_PLAN]
    assert calls == [it for it in before if it.get("name") == UPDATE_PLAN]  # untouched
    last = _text(_outputs(out)[-1])
    assert "version 2" in last and "1. [done] everything" in last
    assert "sweep both subnets" not in last


def test_no_plan_yet_means_nothing_attached():
    store = EvidenceStore("t")
    items = _history(2)
    assert _apply(ContextFilter(store, show_plan=True), items) == items


def test_filter_with_plan_is_idempotent():
    store = EvidenceStore("t")
    store.save_plan(PLAN_V1)
    flt = ContextFilter(store, drop_reasoning=True, show_plan=True)
    once = _apply(flt, _history(3))
    assert _apply(flt, once) == once


def test_plan_and_stubs_work_together():
    """Old results still become stubs; the plan goes on the newest result."""
    store = EvidenceStore("t")
    items = _history(0)
    for n in range(1, 11):
        stored = store.add("nmap", "nmap_scan", {"target": f"10.0.0.{n}"}, [{"n": n}])
        items += _turn(n, ref=stored.ref)
    store.save_plan(PLAN_V1)
    out = _outputs(
        _apply(ContextFilter(store, keep_recent=8, drop_reasoning=True, show_plan=True), items)
    )
    assert "full result removed" in _text(out[0]) and "full result removed" in _text(out[1])
    assert "full result removed" not in _text(out[2])
    assert PLAN_MARKER in _text(out[-1]) and PLAN_MARKER not in _text(out[-2])


# ---------------------------------------------------------------------------
# Prompt + config
# ---------------------------------------------------------------------------


class _Profile:
    structured_output = "prompted"


class _Bundle:
    profile = _Profile()
    model = "m"
    settings = None


def test_prompt_has_the_plan_in_the_process_steps():
    from agents import ModelSettings

    _Bundle.settings = ModelSettings()
    instructions = build_exposure_agent(_Bundle(), mcp_servers=[]).instructions
    assert PLAN_SECTION in instructions
    # WHEN to update lives in PROCESS: after the sweep (1), after a section (2c), 2d
    process = instructions[instructions.index("PROCESS") : instructions.index("YOUR PLAN")]
    assert (
        "coverage checklist.\n   Then, BEFORE you scan any host, write your plan with ONE "
        "update_plan call" in process
    )
    assert "your only memory" in process and "How to call it: update_plan" in process
    assert "Then call update_plan with that host's step marked done." in process
    assert "   d. If a step fails or cannot be done" in process and "mark it blocked" in process
    assert process.index("marked done") < process.index("Do not stop after the first")
    assert NET_PROMPT_VERSION == "nx11"


def test_network_settings_default_and_read_from_yaml():
    assert AgentConfig().network.drop_old_thinking is False
    assert AgentConfig(network={"drop_old_thinking": True}).network.drop_old_thinking
