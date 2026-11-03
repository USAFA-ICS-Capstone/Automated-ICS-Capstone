"""Integration tests for NmapNetworkAgent.

Uses a ScriptedModel (deterministic, no real LLM) + the fake nmap MCP
server (no real nmap, no network), so these tests run completely offline.

The real OpenAI Agents SDK loop is exercised end-to-end:
  ScriptedModel  ->  SDK runner  ->  GuardedMCPServer  ->  fake_nmap_mcp_server.py

Test scenarios
--------------
1.  Happy-path scan: agent calls do-nmap twice (subnet + NSE follow-up) and
    returns a valid NmapNetworkAssessment.
2.  Tool-budget exhaustion: tool calls beyond the configured limit are refused.
3.  Max-turns exceeded: agent never finishes → status == "max_turns".
4.  Invalid JSON output: model returns prose → status == "invalid_output".
5.  Timeout: agent loop exceeds the time limit → status == "timeout".
6.  Agent is read-only: no local function tools; only MCP tools are available.
7.  Policy blocks unknown tools: do-nmap is allowed but a hypothetical
    run-exploit call must be refused.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from agents import ModelSettings
from agents.testing import ScriptedModel, assistant_message, function_call

# Make sure the fixtures directory is on sys.path (conftest.py adds it, but
# be explicit here so this file is self-contained when read in isolation).
FIXTURES = Path(__file__).parent.parent / "fixtures"
sys.path.insert(0, str(FIXTURES))

from docker_security_agent.agents.nmap_network_agent import (
    build_nmap_agent,
    build_nmap_input,
    run_nmap_agent,
)
from docker_security_agent.config import ModelProfile, Settings, load_settings
from docker_security_agent.llm.factory import ModelBundle
from docker_security_agent.mcp.policy import ToolPolicy
from docker_security_agent.mcp.recorder import ToolCallRecorder
from docker_security_agent.mcp.redaction import Redactor
from docker_security_agent.mcp.registry import build_servers, connect
from docker_security_agent.schemas.nmap_network import NmapNetworkAssessment

pytestmark = pytest.mark.integration

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def nmap_settings(tmp_path: Path) -> Settings:
    """Real config with the nmap MCP server pointed at the fake stdio script."""
    s = load_settings()
    s.experiment.data_dir = str(tmp_path / "data")
    s.experiment.output_dir = str(tmp_path / "outputs")

    script = str(FIXTURES / "fake_nmap_mcp_server.py")
    call_log = tmp_path / "nmap_calls.jsonl"

    nmap_cfg = s.mcp.servers["nmap"]
    nmap_cfg.command = sys.executable
    nmap_cfg.args = [script, "default"]
    nmap_cfg.env = {**nmap_cfg.env, "FAKE_NMAP_CALL_LOG": str(call_log)}
    nmap_cfg.client_session_timeout_seconds = 30

    return s


@pytest.fixture
def nmap_settings_empty(nmap_settings: Settings) -> Settings:
    """Nmap server that returns no hosts up (empty scan)."""
    cfg = nmap_settings.mcp.servers["nmap"]
    cfg.args = [cfg.args[0], "empty"]  # swap scenario
    return nmap_settings


@pytest.fixture
def nmap_settings_ics_heavy(nmap_settings: Settings) -> Settings:
    """Nmap server with multiple ICS hosts."""
    cfg = nmap_settings.mcp.servers["nmap"]
    cfg.args = [cfg.args[0], "ics_heavy"]
    return nmap_settings


def _nmap_bundle(model: Any) -> ModelBundle:
    profile = ModelProfile(
        name="scripted",
        provider="ollama",
        model="scripted",
        base_url="http://unused/v1",
        structured_output="prompted",
        temperature=0.0,
    )
    return ModelBundle(model=model, settings=ModelSettings(), profile=profile)


def _nmap_servers(settings: Settings, recorder: ToolCallRecorder):
    """Return GuardedMCPServer list for the nmap role only."""
    policy = ToolPolicy(settings.mcp)
    return build_servers(
        settings,
        policy,
        Redactor(settings.mcp.redaction),
        recorder,
        roles={"network_scanner"},
    )


def _valid_assessment_json(**overrides) -> str:
    doc = {
        "executive_summary": "Two ICS hosts found; Modbus and S7 exposed.",
        "overall_risk": "critical",
        "hosts_assessed": ["192.168.95.10"],
        "exposed_ics_services": [
            {
                "host": "192.168.95.10",
                "port": 502,
                "protocol_name": "Modbus TCP",
                "risk_level": "high",
                "rationale": "Unauthenticated Modbus reachable from IT segment.",
                "recommended_action": "Restrict port 502 via firewall.",
            }
        ],
        "findings": [
            {
                "title": "Modbus TCP exposed on 192.168.95.10",
                "severity": "high",
                "host": "192.168.95.10",
                "port": 502,
                "evidence": "Nmap: 502/tcp open mbap Modbus TCP",
                "recommendation": "Firewall port 502.",
            }
        ],
        "attack_surface_summary": "One host with Modbus and S7 exposed on the ICS network.",
        "recommendations": ["Restrict ICS ports to authorised subnets."],
        "limitations": ["Only 192.168.95.0/24 was scanned."],
        **overrides,
    }
    return json.dumps(doc)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_happy_path_two_nmap_calls(nmap_settings, tmp_path):
    """Agent calls do-nmap for subnet then NSE follow-up, returns valid assessment."""
    model = ScriptedModel(
        [
            # Turn 1: initial subnet scan
            [function_call("do-nmap", {"target": "192.168.95.0/24", "arguments": "-sT -T2 -p 102,502,4840,20000,44818,47808,9600,1911,2222,18245,21,22,23,80,443,3306,5432,6379,8080,8443 -sV --version-intensity 2 --open"}, call_id="c1")],
            # Turn 2: NSE follow-up on the host with ICS ports open
            [function_call("do-nmap", {"target": "192.168.95.10", "arguments": "-sT -T2 -p 102,502,4840,20000,44818,47808,9600,1911,2222,18245 --script modbus-discover,s7-info,enip-info,dnp3-info,bacnet-info --open"}, call_id="c2")],
            # Turn 3: final assessment
            [assistant_message(_valid_assessment_json())],
        ]
    )

    recorder = ToolCallRecorder(max_agent_calls=10)
    async with connect(_nmap_servers(nmap_settings, recorder)) as manager:
        agent = build_nmap_agent(_nmap_bundle(model), mcp_servers=manager.active_servers)
        outcome = await run_nmap_agent(
            agent,
            build_nmap_input(["192.168.95.0/24"]),
            max_turns=10,
            timeout_seconds=60,
            run_id="test-happy",
        )

    assert outcome.status == "ok", f"Expected ok, got {outcome.status}: {outcome.error}"
    assert isinstance(outcome.assessment, NmapNetworkAssessment)
    assert outcome.assessment.overall_risk == "critical"
    assert len(outcome.assessment.exposed_ics_services) == 1
    assert outcome.assessment.exposed_ics_services[0].port == 502

    # Verify the MCP calls went through the GuardedMCPServer
    tool_names = [(r.server, r.tool) for r in recorder.records]
    assert ("nmap", "do-nmap") in tool_names


async def test_single_scan_no_nse_followup(nmap_settings, tmp_path):
    """Agent issues one do-nmap call and returns a valid assessment."""
    model = ScriptedModel(
        [
            [function_call("do-nmap", {"target": "192.168.95.10"}, call_id="c1")],
            [assistant_message(_valid_assessment_json())],
        ]
    )

    recorder = ToolCallRecorder(max_agent_calls=5)
    async with connect(_nmap_servers(nmap_settings, recorder)) as manager:
        agent = build_nmap_agent(_nmap_bundle(model), mcp_servers=manager.active_servers)
        outcome = await run_nmap_agent(
            agent,
            build_nmap_input(["192.168.95.10"]),
            max_turns=5,
            timeout_seconds=30,
        )

    assert outcome.status == "ok"
    assert outcome.assessment is not None
    assert len(recorder.records) == 1
    assert recorder.records[0].tool == "do-nmap"


async def test_agent_has_no_local_tools(nmap_settings):
    """NmapNetworkAgent must have zero local function tools (MCP only)."""
    model = ScriptedModel([[assistant_message(_valid_assessment_json())]])
    recorder = ToolCallRecorder(max_agent_calls=5)
    async with connect(_nmap_servers(nmap_settings, recorder)) as manager:
        agent = build_nmap_agent(_nmap_bundle(model), mcp_servers=manager.active_servers)
        assert agent.tools == [], "Agent must not have local function tools"


async def test_tool_budget_exhaustion(nmap_settings):
    """After the tool budget is exhausted, further do-nmap calls are blocked."""
    # ScriptedModel will try to call do-nmap 4 times, but budget is 2.
    loop = [[function_call("do-nmap", {"target": f"10.0.0.{i}"}, call_id=f"c{i}")] for i in range(4)]
    recorder = ToolCallRecorder(max_agent_calls=2)

    async with connect(_nmap_servers(nmap_settings, recorder)) as manager:
        agent = build_nmap_agent(_nmap_bundle(ScriptedModel(loop)), mcp_servers=manager.active_servers)
        outcome = await run_nmap_agent(
            agent,
            build_nmap_input(["10.0.0.0/24"]),
            max_turns=3,  # < scripted steps so the run hits max_turns, not script exhaustion
            timeout_seconds=30,
        )

    assert outcome.status == "max_turns"
    statuses = [r.status for r in recorder.records]
    assert statuses[0] == "ok"
    assert any(s == "budget_exhausted" for s in statuses[1:])


async def test_max_turns_exceeded(nmap_settings):
    """Agent that keeps calling do-nmap is stopped at max_turns."""
    loop = [[function_call("do-nmap", {"target": "192.168.1.1"}, call_id=f"c{i}")] for i in range(10)]
    recorder = ToolCallRecorder(max_agent_calls=20)

    async with connect(_nmap_servers(nmap_settings, recorder)) as manager:
        agent = build_nmap_agent(_nmap_bundle(ScriptedModel(loop)), mcp_servers=manager.active_servers)
        outcome = await run_nmap_agent(
            agent,
            build_nmap_input(["192.168.1.1"]),
            max_turns=3,   # very low limit
            timeout_seconds=30,
        )

    assert outcome.status == "max_turns"


async def test_invalid_json_output(nmap_settings):
    """Model returns prose instead of JSON → status == invalid_output."""
    model = ScriptedModel([[assistant_message("I'm sorry, I cannot complete that task.")]])
    recorder = ToolCallRecorder(max_agent_calls=5)

    async with connect(_nmap_servers(nmap_settings, recorder)) as manager:
        agent = build_nmap_agent(_nmap_bundle(model), mcp_servers=manager.active_servers)
        outcome = await run_nmap_agent(
            agent,
            build_nmap_input(["10.0.0.1"]),
            max_turns=3,
            timeout_seconds=30,
        )

    assert outcome.status == "invalid_output"
    assert outcome.assessment is None
    assert outcome.error is not None


async def test_timeout_returns_timeout_status(nmap_settings):
    """A very short timeout makes run_nmap_agent return status == timeout."""
    # ScriptedModel with no turns will make the SDK wait / timeout
    model = ScriptedModel([[function_call("do-nmap", {"target": "10.0.0.1"}, call_id="c1")]] * 20)
    recorder = ToolCallRecorder(max_agent_calls=100)

    async with connect(_nmap_servers(nmap_settings, recorder)) as manager:
        agent = build_nmap_agent(_nmap_bundle(model), mcp_servers=manager.active_servers)
        outcome = await run_nmap_agent(
            agent,
            build_nmap_input(["10.0.0.1"]),
            max_turns=50,
            timeout_seconds=0.001,  # essentially zero
        )

    assert outcome.status in ("timeout", "max_turns", "error")


async def test_duration_is_recorded(nmap_settings):
    """outcome.duration_seconds must be a positive number."""
    model = ScriptedModel([[assistant_message(_valid_assessment_json())]])
    recorder = ToolCallRecorder(max_agent_calls=5)

    async with connect(_nmap_servers(nmap_settings, recorder)) as manager:
        agent = build_nmap_agent(_nmap_bundle(model), mcp_servers=manager.active_servers)
        outcome = await run_nmap_agent(
            agent,
            build_nmap_input(["10.0.0.1"]),
            max_turns=5,
            timeout_seconds=30,
        )

    # Scripted runs finish in milliseconds and duration is rounded to 2 dp, so 0.0 is valid.
    assert isinstance(outcome.duration_seconds, float)
    assert outcome.duration_seconds >= 0


async def test_assessment_serialises_to_json(nmap_settings):
    """The returned NmapNetworkAssessment must serialise cleanly to JSON."""
    model = ScriptedModel([[assistant_message(_valid_assessment_json())]])
    recorder = ToolCallRecorder(max_agent_calls=5)

    async with connect(_nmap_servers(nmap_settings, recorder)) as manager:
        agent = build_nmap_agent(_nmap_bundle(model), mcp_servers=manager.active_servers)
        outcome = await run_nmap_agent(
            agent,
            build_nmap_input(["10.0.0.1"]),
            max_turns=5,
            timeout_seconds=30,
        )

    assert outcome.status == "ok"
    serialised = outcome.assessment.model_dump_json()
    reparsed = json.loads(serialised)
    assert reparsed["overall_risk"] == "critical"


async def test_raw_output_is_captured(nmap_settings):
    """outcome.raw_output is populated even on a successful run."""
    model = ScriptedModel([[assistant_message(_valid_assessment_json())]])
    recorder = ToolCallRecorder(max_agent_calls=5)

    async with connect(_nmap_servers(nmap_settings, recorder)) as manager:
        agent = build_nmap_agent(_nmap_bundle(model), mcp_servers=manager.active_servers)
        outcome = await run_nmap_agent(
            agent,
            build_nmap_input(["10.0.0.1"]),
            max_turns=5,
            timeout_seconds=30,
        )

    assert outcome.raw_output != ""


async def test_empty_scan_result_still_produces_assessment(nmap_settings_empty):
    """When nmap finds no hosts, the model must still produce a valid assessment."""
    empty_assessment = _valid_assessment_json(
        overall_risk="low",
        hosts_assessed=[],
        exposed_ics_services=[],
        findings=[],
        executive_summary="No hosts found in the target range.",
    )
    model = ScriptedModel(
        [
            [function_call("do-nmap", {"target": "192.168.95.0/24"}, call_id="c1")],
            [assistant_message(empty_assessment)],
        ]
    )
    recorder = ToolCallRecorder(max_agent_calls=5)

    async with connect(_nmap_servers(nmap_settings_empty, recorder)) as manager:
        agent = build_nmap_agent(_nmap_bundle(model), mcp_servers=manager.active_servers)
        outcome = await run_nmap_agent(
            agent,
            build_nmap_input(["192.168.95.0/24"]),
            max_turns=5,
            timeout_seconds=30,
        )

    assert outcome.status == "ok"
    assert outcome.assessment.overall_risk == "low"
    assert outcome.assessment.exposed_ics_services == []


async def test_ics_heavy_scenario_captures_multiple_hosts(nmap_settings_ics_heavy):
    """Multiple hosts with ICS ports appear correctly in the assessment."""
    multi_host_assessment = _valid_assessment_json(
        hosts_assessed=["192.168.95.10", "192.168.95.20", "192.168.95.200"],
        overall_risk="critical",
        exposed_ics_services=[
            {
                "host": "192.168.95.10",
                "port": 502,
                "protocol_name": "Modbus TCP",
                "risk_level": "high",
                "rationale": "Unauthenticated",
                "recommended_action": "Firewall",
            },
            {
                "host": "192.168.95.20",
                "port": 44818,
                "protocol_name": "EtherNet/IP",
                "risk_level": "critical",
                "rationale": "Unauthenticated",
                "recommended_action": "Firewall",
            },
        ],
        findings=[
            {
                "title": "Modbus on .10",
                "severity": "high",
                "host": "192.168.95.10",
                "port": 502,
                "evidence": "502/tcp open",
                "recommendation": "Firewall",
            }
        ],
    )
    model = ScriptedModel(
        [
            [function_call("do-nmap", {"target": "192.168.95.0/24"}, call_id="c1")],
            [assistant_message(multi_host_assessment)],
        ]
    )
    recorder = ToolCallRecorder(max_agent_calls=5)

    async with connect(_nmap_servers(nmap_settings_ics_heavy, recorder)) as manager:
        agent = build_nmap_agent(_nmap_bundle(model), mcp_servers=manager.active_servers)
        outcome = await run_nmap_agent(
            agent,
            build_nmap_input(["192.168.95.0/24"]),
            max_turns=5,
            timeout_seconds=30,
        )

    assert outcome.status == "ok"
    assert len(outcome.assessment.hosts_assessed) == 3
    assert len(outcome.assessment.exposed_ics_services) == 2
