"""The agent loop and the full pipeline, with a scripted (mock) model.

The OpenAI Agents SDK ships ``agents.testing.ScriptedModel``: a deterministic
``Model`` that returns pre-defined outputs (tool calls, then a final message).
Using it, these tests run the REAL SDK agent loop, REAL MCP subprocesses (the
fake servers), the real evidence tools, validation, SQLite and reporting -
with no LLM, no Docker and no paid API.
"""

import json

import pytest
from agents import ModelSettings, SQLiteSession
from agents.testing import ScriptedModel, assistant_message, function_call
from builders import build_snapshot

from docker_security_agent.agents.security_assessment import (
    EvidenceStore,
    build_agent,
    build_evidence_tools,
    run_agent,
)
from docker_security_agent.config import ModelProfile
from docker_security_agent.llm.factory import ModelBundle
from docker_security_agent.mcp.policy import ToolPolicy
from docker_security_agent.mcp.recorder import ToolCallRecorder
from docker_security_agent.mcp.redaction import Redactor
from docker_security_agent.mcp.registry import DockerEndpointStatus, build_servers, connect
from docker_security_agent.memory.repository import AssessmentRepository
from docker_security_agent.pipeline import AssessOptions, run_assessment
from docker_security_agent.security import rules

pytestmark = pytest.mark.integration


def _bundle(model) -> ModelBundle:
    profile = ModelProfile(
        name="scripted",
        provider="ollama",
        model="scripted",
        base_url="http://unused/v1",
        structured_output="prompted",
    )
    return ModelBundle(model=model, settings=ModelSettings(), profile=profile)


def _final_json(finding_id: str, concern_resource: str = "router") -> str:
    return json.dumps(
        {
            "executive_summary": "Docker socket on simulation gives host control; CVE-2026-103111.",
            "overall_risk": "critical",
            "prioritized_findings": [
                {"finding_id": finding_id, "rank": 1, "rationale": "simulation controls the host"},
                {"finding_id": "F-MADE-UP", "rank": 2, "rationale": "hallucinated"},
            ],
            "potential_concerns": [
                {
                    "title": "Router bridges DMZ and ICS with NET_RAW",
                    "resource_name": concern_resource,
                    "category": "network-segmentation",
                    "severity": "high",
                    "explanation": "pivot",
                    "remediation": "split",
                    "evidence_refs": ["HostConfig.CapAdd"],
                }
            ],
            "recommendations": ["Remove the docker.sock mount from simulation"],
            "limitations": ["Scripted model"],
        }
    )


async def test_agent_uses_evidence_and_mcp_tools(fake_mcp_settings, tmp_path):
    settings = fake_mcp_settings
    snap = build_snapshot(settings)
    findings = rules.evaluate(snap, settings.rules)
    socket_id = next(f.id for f in findings if f.rule_id == "C008")

    model = ScriptedModel(
        [
            [
                function_call(
                    "get_rule_findings",
                    {"min_severity": "critical", "resource_name": ""},
                    call_id="c1",
                )
            ],
            [function_call("container_inspect", {"id_or_name": "router"}, call_id="c2")],
            [assistant_message(_final_json(socket_id))],
        ]
    )
    recorder = ToolCallRecorder(10)
    policy = ToolPolicy(settings.mcp)
    servers = build_servers(
        settings, policy, Redactor(settings.mcp.redaction), recorder, roles={"docker_inspection"}
    )
    session = SQLiteSession("t1", tmp_path / "s.db")
    async with connect(servers) as manager:
        store = EvidenceStore(snapshot=snap, findings=findings, scans=[])
        agent = build_agent(
            _bundle(model),
            mcp_servers=manager.active_servers,
            evidence_tools=build_evidence_tools(store, recorder),
        )
        outcome = await run_agent(
            agent,
            "assess",
            max_turns=10,
            timeout_seconds=60,
            session=session,
            tracing_enabled=False,
            run_id="t1",
        )

    assert outcome.status == "ok", outcome.error
    assert outcome.assessment.prioritized_findings[0].finding_id == socket_id
    assert [(r.server, r.tool) for r in recorder.records] == [
        ("local", "get_rule_findings"),
        ("docker", "container_inspect"),
    ]
    # The model saw redacted data only.
    tool_output = str(model.calls[2].input)
    assert "FWUI_SECRET_KEY=<redacted>" in tool_output
    assert "some-long-secret-you-generate" not in tool_output
    # Conversation persisted in the SDK SQLite session.
    assert len(await session.get_items()) >= 5


async def test_tool_budget_and_turn_limit(settings):
    snap = build_snapshot(settings)
    store = EvidenceStore(snapshot=snap, findings=[], scans=[])
    recorder = ToolCallRecorder(max_agent_calls=1)
    loop = [[function_call("get_inventory_overview", {}, call_id=f"c{i}")] for i in range(5)]
    agent = build_agent(
        _bundle(ScriptedModel(loop)),
        mcp_servers=[],
        evidence_tools=build_evidence_tools(store, recorder),
    )
    outcome = await run_agent(
        agent,
        "x",
        max_turns=3,
        timeout_seconds=30,
        session=None,
        tracing_enabled=False,
        run_id="t2",
    )
    assert outcome.status == "max_turns"
    statuses = [r.status for r in recorder.records]
    assert statuses[0] == "ok" and set(statuses[1:]) == {"budget_exhausted"}


async def test_invalid_final_output_is_reported(settings):
    store = EvidenceStore(snapshot=build_snapshot(settings), findings=[], scans=[])
    model = ScriptedModel([[assistant_message("Sorry, I cannot help with that.")]])
    agent = build_agent(
        _bundle(model),
        mcp_servers=[],
        evidence_tools=build_evidence_tools(store, ToolCallRecorder(5)),
    )
    outcome = await run_agent(
        agent,
        "x",
        max_turns=3,
        timeout_seconds=30,
        session=None,
        tracing_enabled=False,
        run_id="t3",
    )
    assert outcome.status == "invalid_output" and outcome.assessment is None


@pytest.fixture
def pipeline_env(fake_mcp_settings, monkeypatch):
    """Run pipeline.run_assessment against the fake MCP servers + a scripted model."""
    import docker_security_agent.pipeline as pipeline

    monkeypatch.setattr(
        pipeline,
        "check_docker_endpoint",
        lambda s: DockerEndpointStatus(
            docker_host=s.mcp.docker_host,
            is_tcp=True,
            reachable=True,
            filtered=True,
            docker_version="29.7.2",
        ),
    )
    monkeypatch.setattr(pipeline, "trivy_db_status", lambda: {"UpdatedAt": "fixture"})
    holder = {}

    async def fake_prepare(settings, opts):
        return _bundle(holder["model"]) if opts.use_agent else None

    monkeypatch.setattr(pipeline, "_prepare_model", fake_prepare)
    return fake_mcp_settings, holder


async def test_full_live_pipeline_with_fakes(pipeline_env):
    settings, holder = pipeline_env
    snap = build_snapshot(settings)
    socket_id = next(f.id for f in rules.evaluate(snap, settings.rules) if f.rule_id == "C008")
    holder["model"] = ScriptedModel(
        [
            [function_call("get_inventory_overview", {}, call_id="c1")],
            [assistant_message(_final_json(socket_id, concern_resource="ghost-container"))],
        ]
    )
    settings.experiment.scan.max_images = 3

    result = await run_assessment(settings, AssessOptions(model_profile="scripted"))

    assert result.status == "completed"
    r = result.report
    assert r.summary.risk_source == "agent" and r.summary.overall_risk == "critical"
    assert r.prioritized[0].finding_id == socket_id
    assert len(r.prioritized) == 1  # hallucinated F-MADE-UP dropped
    assert [c.resource_name for c in r.rejected_agent_claims] == ["ghost-container"]
    assert len(r.vulnerabilities) == 3
    assert result.json_path.exists() and result.md_path.exists()
    assert any("F-MADE-UP" in e for e in r.errors)

    repo = AssessmentRepository(settings.assessment_db_path)
    run = repo.get_run(result.run_id)
    assert run["status"] == "completed" and run["agent_status"] == "ok"
    assert run["snapshot_id"] == r.snapshot_id
    calls = repo.load_tool_calls(result.run_id)
    assert {c["phase"] for c in calls} == {"collector", "agent"}
    assert repo.load_report(result.run_id).run_id == result.run_id
    repo.close()


async def test_replay_reuses_stored_evidence_without_docker(pipeline_env, monkeypatch):
    settings, holder = pipeline_env
    # First a deterministic live run to store snapshot + scans.
    settings.experiment.scan.max_images = 2
    first = await run_assessment(settings, AssessOptions(use_agent=False))
    assert first.report.summary.risk_source == "deterministic"

    # Replay must not touch Docker / MCP at all.
    import docker_security_agent.pipeline as pipeline

    def no_docker(*a, **k):
        raise AssertionError("replay must not start MCP servers")

    monkeypatch.setattr(pipeline, "build_servers", no_docker)
    holder["model"] = ScriptedModel(
        [
            [
                function_call(
                    "get_image_vulnerabilities",
                    {
                        "image": "fortiphyd/grfics-simulation:latest",
                        "min_severity": "HIGH",
                        "limit": 5,
                    },
                    call_id="c1",
                )
            ],
            [assistant_message(_final_json("F-NOT-REAL"))],
        ]
    )
    replay = await run_assessment(
        settings, AssessOptions(model_profile="scripted", snapshot_id=first.report.snapshot_id)
    )
    assert replay.report.snapshot_id == first.report.snapshot_id
    assert len(replay.report.vulnerabilities) == len(first.report.vulnerabilities)
    assert {f.id for f in replay.report.findings} == {f.id for f in first.report.findings}
    # Only fake IDs were prioritised -> deterministic fallback ordering.
    assert replay.report.prioritized[0].ranked_by == "deterministic"


async def test_failed_agent_still_produces_report(pipeline_env):
    settings, holder = pipeline_env
    holder["model"] = ScriptedModel([RuntimeError("model server crashed")])
    result = await run_assessment(settings, AssessOptions(model_profile="scripted", scan=False))
    assert result.status == "completed_with_errors"
    assert result.report.findings  # deterministic evidence survives
    assert result.report.summary.risk_source == "deterministic"
    assert any("model server crashed" in e for e in result.report.errors)


async def test_missing_optional_args_and_informative_tool_errors(settings):
    """Regression: qwen3 omitted `resource_name` and got only a generic SDK error.

    Optional arguments now have defaults, and a genuinely bad call returns the
    real validation error (so the model can fix it) and is recorded.
    """
    snap = build_snapshot(settings)
    findings = rules.evaluate(snap, settings.rules)
    store = EvidenceStore(snapshot=snap, findings=findings, scans=[])
    recorder = ToolCallRecorder(10)
    model = ScriptedModel(
        [
            [function_call("get_rule_findings", {"min_severity": "critical"}, call_id="c1")],
            [function_call("get_container_details", {}, call_id="c2")],  # required arg missing
            [assistant_message(_final_json(findings[0].id))],
        ]
    )
    agent = build_agent(
        _bundle(model), mcp_servers=[], evidence_tools=build_evidence_tools(store, recorder)
    )
    outcome = await run_agent(
        agent,
        "x",
        max_turns=5,
        timeout_seconds=30,
        session=None,
        tracing_enabled=False,
        run_id="t4",
    )
    assert outcome.status == "ok"
    first_output = str(model.calls[1].input)
    assert "F-C008" in first_output  # call without resource_name worked
    second_output = str(model.calls[2].input)
    assert "Tool call failed" in second_output and "container_name" in second_output
    assert [r.status for r in recorder.records] == ["ok", "error"]
