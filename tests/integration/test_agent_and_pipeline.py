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
from docker_security_agent.config import ConfigError, ModelProfile
from docker_security_agent.llm.factory import ModelBundle
from docker_security_agent.mcp.policy import ToolPolicy
from docker_security_agent.mcp.recorder import ToolCallRecorder
from docker_security_agent.mcp.redaction import Redactor
from docker_security_agent.mcp.registry import DockerEndpointStatus, build_servers, connect
from docker_security_agent.memory.repository import AssessmentRepository
from docker_security_agent.pipeline import AssessOptions, options_from_manifest, run_assessment
from docker_security_agent.security import rules

pytestmark = pytest.mark.integration


def _bundle(model) -> ModelBundle:
    profile = ModelProfile(
        name="scripted",
        provider="ollama",
        model="scripted",
        base_url="http://unused/v1",
        structured_output="prompted",
        temperature=0.2,
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
    assert replay.report.docker_endpoint is None  # replay never touches Docker


def _raw_socket_endpoint(monkeypatch, settings):
    """Simulate require_proxy: false with docker_host pointing at the raw socket."""
    import docker_security_agent.pipeline as pipeline

    settings.mcp.require_proxy = False
    settings.mcp.docker_host = "unix:///var/run/docker.sock"
    monkeypatch.setattr(
        pipeline,
        "check_docker_endpoint",
        lambda s: DockerEndpointStatus(docker_host=s.mcp.docker_host, is_tcp=False),
    )


async def test_proxy_requirement_disabled_is_recorded_and_warned(pipeline_env, monkeypatch):
    settings, _ = pipeline_env
    _raw_socket_endpoint(monkeypatch, settings)
    warnings: list[str] = []
    progress: list[str] = []

    result = await run_assessment(
        settings,
        AssessOptions(use_agent=False, scan=False, warn=warnings.append, progress=progress.append),
    )

    # prominent warning, and no false "read-only proxy" claim
    assert len(warnings) == 1 and "require_proxy is disabled" in warnings[0]
    assert "unix:///var/run/docker.sock" in warnings[0]
    assert not any("read-only proxy" in m for m in progress)

    # report.json + report.md
    ep = result.report.docker_endpoint
    assert ep.require_proxy is False and ep.proxy_verified is False
    assert ep.docker_host == "unix:///var/run/docker.sock"
    assert warnings[0] in result.report.errors
    md = result.md_path.read_text()
    assert "[!CAUTION]" in md and "require_proxy is disabled" in md
    assert "NOT verified as read-only proxy" in md

    # run provenance in SQLite
    repo = AssessmentRepository(settings.assessment_db_path)
    run = repo.get_run(result.run_id)
    assert json.loads(run["docker_endpoint_json"]) == {
        "docker_host": "unix:///var/run/docker.sock",
        "require_proxy": False,
        "proxy_verified": False,
        "docker_version": "",
    }
    assert warnings[0] in json.loads(run["errors_json"])
    repo.close()


async def test_proxy_provenance_survives_a_failed_run(pipeline_env, monkeypatch):
    import docker_security_agent.pipeline as pipeline

    settings, _ = pipeline_env
    _raw_socket_endpoint(monkeypatch, settings)

    def broken(*a, **k):
        raise RuntimeError("MCP launch failed")

    monkeypatch.setattr(pipeline, "build_servers", broken)
    with pytest.raises(RuntimeError):
        await run_assessment(settings, AssessOptions(use_agent=False, scan=False))

    repo = AssessmentRepository(settings.assessment_db_path)
    [row] = repo.list_runs()
    run = repo.get_run(row["run_id"])
    assert run["status"] == "failed"
    assert json.loads(run["docker_endpoint_json"])["require_proxy"] is False
    repo.close()


async def test_proxied_run_records_verified_endpoint_without_warning(pipeline_env):
    settings, _ = pipeline_env
    warnings: list[str] = []
    result = await run_assessment(
        settings, AssessOptions(use_agent=False, scan=False, warn=warnings.append)
    )
    assert warnings == []
    ep = result.report.docker_endpoint
    assert ep.require_proxy is True and ep.proxy_verified is True
    assert "[!CAUTION]" not in result.md_path.read_text()
    repo = AssessmentRepository(settings.assessment_db_path)
    assert json.loads(repo.get_run(result.run_id)["docker_endpoint_json"])["proxy_verified"]
    repo.close()


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


# ---------------------------------------------------------------------------
# Run manifests
# ---------------------------------------------------------------------------


def _scripted_run(holder, socket_id):
    holder["model"] = ScriptedModel(
        [
            [function_call("get_inventory_overview", {}, call_id="c1")],
            [assistant_message(_final_json(socket_id))],
        ]
    )


async def test_live_run_writes_immutable_manifest(pipeline_env):
    settings, holder = pipeline_env
    settings.experiment.scan.max_images = 2
    snap = build_snapshot(settings)
    _scripted_run(
        holder, next(f.id for f in rules.evaluate(snap, settings.rules) if f.rule_id == "C008")
    )

    result = await run_assessment(settings, AssessOptions(model_profile="scripted"))

    # file: written once, read-only, self-verifying
    path = result.manifest_path
    assert path == result.json_path.parent / "manifest.json"
    assert not path.stat().st_mode & 0o222
    doc = json.loads(path.read_text())
    m = doc["manifest"]
    assert m["run_id"] == result.run_id
    exp = m["experiment"]
    assert exp["scenario_id"] == settings.experiment.scenario_id
    assert exp["evidence"]["snapshot_id"] == result.report.snapshot_id
    assert exp["prompt_bundle"]["version"] == "v3"
    assert exp["schema_versions"]["db_schema_version"] >= 3
    assert exp["models"]["assessment_agent"]["model"] == "scripted"
    assert exp["sampling"]["assessment_agent"]["temperature"] == 0.2
    assert exp["agent"]["max_turns"] == settings.agent.limits.max_turns
    assert exp["logging"]["record_tool_calls"] and exp["logging"]["record_conversation"]
    assert m["framework"]["commit"]  # git HEAD (or "unknown")
    assert m["acquisition"]["mode"] == "live"
    assert m["acquisition"]["docker_endpoint"]["proxy_verified"] is True

    # SQLite: same hashes, and the pinned scans are exactly the ones this run saved
    repo = AssessmentRepository(settings.assessment_db_path)
    run = repo.get_run(result.run_id)
    assert run["manifest_sha256"] == doc["manifest_sha256"] == result.report.manifest_sha256
    assert run["config_sha256"] == doc["config_sha256"] == result.report.config_sha256
    saved = [
        r["scan_id"]
        for r in repo.conn.execute("SELECT scan_id FROM scans WHERE run_id = ?", (result.run_id,))
    ]
    assert exp["evidence"]["scan_ids"] == sorted(saved) and len(saved) == 2
    with pytest.raises(ValueError):  # write-once
        repo.save_manifest(result.run_id, "{}", "x", "y")
    repo.close()

    # report
    assert doc["manifest_sha256"] in result.md_path.read_text()


async def test_rerun_from_manifest_reproduces_configuration(pipeline_env):
    settings, holder = pipeline_env
    settings.experiment.scan.max_images = 2
    snap = build_snapshot(settings)
    socket_id = next(f.id for f in rules.evaluate(snap, settings.rules) if f.rule_id == "C008")
    _scripted_run(holder, socket_id)
    first = await run_assessment(
        settings, AssessOptions(model_profile="scripted", objective="Custom objective")
    )
    # A later live run of the same environment adds newer scans to the same snapshot.
    later = await run_assessment(settings, AssessOptions(use_agent=False))
    assert later.report.snapshot_id == first.report.snapshot_id

    # Local config drifts after the run; the manifest must win.
    settings.agent.limits.max_turns = 3
    settings.rules.disabled_rules = ["C008"]

    import docker_security_agent.pipeline as pipeline

    def no_docker(*a, **k):
        raise AssertionError("a manifest re-run must not start MCP servers")

    pipeline_build_servers = pipeline.build_servers
    pipeline.build_servers = no_docker
    try:
        new_settings, opts = options_from_manifest(settings, str(first.manifest_path))
        _scripted_run(holder, socket_id)
        rerun = await run_assessment(new_settings, opts)
    finally:
        pipeline.build_servers = pipeline_build_servers

    a = json.loads(first.manifest_path.read_text())
    b = json.loads(rerun.manifest_path.read_text())
    assert b["config_sha256"] == a["config_sha256"]  # same experimental configuration
    assert b["manifest_sha256"] != a["manifest_sha256"]  # but a distinct run record
    assert b["manifest"]["experiment"]["evidence"] == a["manifest"]["experiment"]["evidence"]
    assert b["manifest"]["replay_of"] == {
        "run_id": first.run_id,
        "manifest_sha256": a["manifest_sha256"],
    }
    assert b["manifest"]["acquisition"]["mode"] == "replay"
    assert {f.id for f in rerun.report.findings} == {f.id for f in first.report.findings}

    # also addressable by run ID
    _, by_id = options_from_manifest(settings, first.run_id)
    assert by_id.replay_of.manifest_sha256 == a["manifest_sha256"]


async def test_rerun_refuses_altered_manifest_or_prompt_drift(pipeline_env, monkeypatch, tmp_path):
    settings, _ = pipeline_env
    first = await run_assessment(settings, AssessOptions(use_agent=False, scan=False))

    # altered file
    doc = json.loads(first.manifest_path.read_text())
    doc["manifest"]["experiment"]["objective"] = "something else"
    altered = tmp_path / "altered.json"
    altered.write_text(json.dumps(doc))
    with pytest.raises(ConfigError, match="modified after the run"):
        options_from_manifest(settings, str(altered))

    # prompt changed since the run
    import docker_security_agent.agents.security_assessment as sa

    monkeypatch.setattr(sa, "INSTRUCTIONS", sa.INSTRUCTIONS + " changed")
    with pytest.raises(ConfigError, match="prompt bundle changed"):
        options_from_manifest(settings, first.run_id)
    _, opts = options_from_manifest(settings, first.run_id, allow_drift=True)
    assert any("prompt bundle changed" in n for n in opts.notes)


# ---------------------------------------------------------------------------
# Range baselines
# ---------------------------------------------------------------------------


async def test_range_baseline_is_checked_and_recorded_in_manifest(pipeline_env):
    from docker_security_agent.inventory.baseline import record_baseline

    settings, holder = pipeline_env
    baseline = record_baseline(settings.data_dir, "clean", build_snapshot(settings))

    result = await run_assessment(
        settings, AssessOptions(use_agent=False, scan=False, range_baseline="clean")
    )
    m = json.loads(result.manifest_path.read_text())["manifest"]
    assert m["experiment"]["range_baseline"] == {
        "name": "clean",
        "fingerprint_sha256": baseline.fingerprint_sha256,
        "baseline_snapshot_id": baseline.snapshot_id,
    }
    assert m["acquisition"]["range_check"]["verified_at"]

    # a manifest re-run carries the baseline forward: same configuration
    new_settings, opts = options_from_manifest(settings, result.run_id)
    rerun = await run_assessment(new_settings, opts)
    a = json.loads(result.manifest_path.read_text())
    b = json.loads(rerun.manifest_path.read_text())
    assert b["config_sha256"] == a["config_sha256"]
    assert b["manifest"]["acquisition"]["range_check"] is None  # replay: nothing re-checked


async def test_range_mismatch_aborts_before_scanning(pipeline_env):
    from docker_security_agent.inventory.baseline import record_baseline
    from docker_security_agent.pipeline import AssessmentAborted

    settings, holder = pipeline_env
    snap = build_snapshot(settings)
    snap.containers = [c for c in snap.containers if c.name != "kali"]
    record_baseline(settings.data_dir, "without-kali", snap)

    with pytest.raises(AssessmentAborted, match="containers.kali: unexpected"):
        await run_assessment(
            settings, AssessOptions(use_agent=False, range_baseline="without-kali")
        )

    repo = AssessmentRepository(settings.assessment_db_path)
    [row] = repo.list_runs()
    calls = repo.load_tool_calls(row["run_id"])
    assert row["status"] == "failed"
    assert not any(c["tool"] == "scan_image" for c in calls)
    assert repo.get_run(row["run_id"])["manifest_sha256"] is None
    repo.close()
    verifications = settings.data_dir / "range-baselines" / "without-kali" / "verifications"
    assert len(list(verifications.glob("*.json"))) == 1  # the failed check is kept


async def test_range_baseline_errors_early(pipeline_env):
    settings, _ = pipeline_env
    with pytest.raises(ConfigError, match="No range baseline named"):
        await run_assessment(settings, AssessOptions(use_agent=False, range_baseline="nope"))
    with pytest.raises(ConfigError, match="cannot be used to replay"):
        await run_assessment(
            settings, AssessOptions(use_agent=False, snapshot_id="x", range_baseline="nope")
        )
