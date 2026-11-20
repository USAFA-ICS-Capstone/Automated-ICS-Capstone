"""h7 replay: the real history of the run that looped, through the old and new filter.

Fixture: tests/fixtures/session_net-20261118-171115-f80b.json - the 52 session items
(1 task, 17 x thinking / tool call / tool result) of the Phase-2 run that repeated two
deduplicated calls until it was stopped. Converted to chat messages with the same
SDK converter the vLLM model uses, so "reasoning on an assistant message" is exactly
what vLLM renders as a <think> block.
"""

import json
from pathlib import Path

from agents.models.chatcmpl_converter import Converter
from agents.run_config import CallModelData, ModelInputData

from docker_security_agent.agents.context_filter import PLAN_MARKER, ContextFilter
from docker_security_agent.mcp.evidence import EvidenceStore

FIXTURE = Path(__file__).parent.parent / "fixtures" / "session_net-20261118-171115-f80b.json"
MODEL = "Qwen/Qwen3-32B"  # the model of that run (reasoning is re-sent only on a match)


def _history():
    return json.loads(FIXTURE.read_text())


def _sent(flt, items):
    data = CallModelData(
        model_data=ModelInputData(input=items, instructions="i"), agent=None, context=None
    )
    return Converter.items_to_messages(flt(data).input, model=MODEL)


def _thinking(messages):
    return [m["reasoning"] for m in messages if m.get("role") == "assistant" and m.get("reasoning")]


def _chars(messages):
    return len(json.dumps(messages))


def test_old_filter_resends_all_17_identical_thinking_blocks():
    """Reproduces the cause: every earlier thinking block goes back to the model."""
    sent = _sent(ContextFilter(EvidenceStore("r")), _history())
    thinking = _thinking(sent)
    assert len(thinking) == 17
    assert len(set(thinking[6:])) <= 3  # turns 7-17: only 3 distinct (copied) texts


def test_new_filter_sends_no_thinking_but_every_call_and_result():
    history = _history()
    store = EvidenceStore("r")
    old = _sent(ContextFilter(store), history)
    new = _sent(ContextFilter(store, drop_reasoning=True), history)
    assert _thinking(new) == []
    def calls(ms):
        return [c for m in ms if m.get("role") == "assistant" for c in m.get("tool_calls") or []]

    def results(ms):
        return [m["content"] for m in ms if m.get("role") == "tool"]

    assert calls(new) == calls(old) and len(calls(new)) == 17
    assert results(new) == results(old) and len(results(new)) == 17
    assert _chars(new) < 0.3 * _chars(old)  # thinking was most of the prompt


def test_new_filter_shows_one_plan_at_the_very_end():
    store = EvidenceStore("r")
    store.save_plan(
        [
            {"text": "sweep 192.168.95.0/24 and 192.168.90.0/24", "status": "done"},
            {"text": "192.168.95.10: read registers, record section", "status": "done"},
            {"text": "192.168.95.11: read registers, record section", "status": "doing"},
            {"text": "final assessment", "status": "todo"},
        ]
    )
    sent = _sent(ContextFilter(store, drop_reasoning=True, show_plan=True), _history())
    with_plan = [m for m in sent if PLAN_MARKER in json.dumps(m)]
    assert len(with_plan) == 1 and with_plan[0] is sent[-1]
    assert sent[-1]["role"] == "tool" and "Not run again" in json.dumps(sent[-1])
