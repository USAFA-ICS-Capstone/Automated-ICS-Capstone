"""SQLite persistence and report generation."""

import json
from datetime import UTC, datetime

import grfics
import pytest

from docker_security_agent.memory.database import SCHEMA_VERSION
from docker_security_agent.memory.repository import AssessmentRepository
from docker_security_agent.reporting.generator import build_report, render_markdown, write_report
from docker_security_agent.schemas.observations import ImageScanResult, ToolCallRecord
from docker_security_agent.schemas.reports import (
    AgentAssessment,
    PrioritizedItem,
    Report,
    RunMetrics,
)
from docker_security_agent.security import rules
from docker_security_agent.security.validation import validate_agent_output
from docker_security_agent.security.vulnerability_parser import (
    count_by_severity,
    parse_findings_page,
    vulnerability_findings,
)


@pytest.fixture
def repo(tmp_path):
    r = AssessmentRepository(tmp_path / "a.db")
    yield r
    r.close()


@pytest.fixture
def scans(snapshot):
    vulns = parse_findings_page(grfics.trivy_findings_page(None, 10))[0]
    image = next(i for i in snapshot.images if i.tags == ["fortiphyd/grfics-plc:latest"])
    return [
        ImageScanResult(
            image_id=image.id,
            image_ref=image.tags[0],
            scanner_version="0.68.2",
            scanned_at=datetime.now(UTC),
            counts=count_by_severity(vulns),
            vulnerabilities=vulns,
        )
    ]


def _create(repo, run_id="run-1"):
    repo.create_run(
        run_id=run_id,
        mode="live",
        objective="obj",
        model_profile="local-qwen",
        model_provider="ollama",
        model_id="qwen3",
        model_config={"temperature": 0.2},
        prompt_version="v1",
        session_id=run_id,
    )


def test_run_lifecycle(repo):
    _create(repo)
    repo.update_run("run-1", status="completed", errors_json=["x"], metrics_json={"a": 1})
    run = repo.get_run("run-1")
    assert run["status"] == "completed" and json.loads(run["errors_json"]) == ["x"]
    assert repo.list_runs()[0]["run_id"] == "run-1"
    with pytest.raises(ValueError):
        repo.update_run("run-1", objective="cannot change")


def test_snapshot_roundtrip_and_dedupe(repo, snapshot):
    repo.save_snapshot(snapshot)
    repo.save_snapshot(snapshot)  # same ID -> stored once
    assert len(repo.list_snapshots()) == 1
    loaded = repo.load_snapshot(snapshot.snapshot_id)
    assert loaded.snapshot_id == snapshot.snapshot_id
    assert loaded.compute_id() == snapshot.snapshot_id
    assert [c.name for c in loaded.containers] == [c.name for c in snapshot.containers]


def test_scans_findings_tool_calls(repo, snapshot, settings, scans):
    _create(repo)
    repo.save_snapshot(snapshot)
    repo.save_scan("run-1", snapshot.snapshot_id, scans[0])
    loaded = repo.load_scans_for_snapshot(snapshot.snapshot_id)
    assert len(loaded) == 1 and len(loaded[0].vulnerabilities) == 3
    assert loaded[0].counts == scans[0].counts

    findings = rules.evaluate(snapshot, settings.rules)
    repo.save_findings("run-1", findings)
    assert {f.id for f in repo.load_findings("run-1")} == {f.id for f in findings}

    repo.save_tool_calls(
        "run-1",
        [
            ToolCallRecord(
                timestamp=datetime.now(UTC),
                phase="agent",
                server="docker",
                tool="container_inspect",
                arguments={"id_or_name": "plc"},
                status="ok",
                duration_ms=12,
            )
        ],
    )
    assert repo.load_tool_calls("run-1")[0]["tool"] == "container_inspect"


def _report(snapshot, settings, scans, validation=None, agent_status="skipped"):
    findings = rules.evaluate(snapshot, settings.rules) + vulnerability_findings(scans, snapshot)
    return build_report(
        run_id="run-x",
        status="completed",
        objective="obj",
        model=None,
        prompt_version="v1",
        mcp_servers=[],
        snapshot=snapshot,
        findings=findings,
        scans=scans,
        validation=validation,
        agent_status=agent_status,
        errors=[],
        metrics=RunMetrics(started_at=datetime.now(UTC)),
    ), findings


def test_report_without_agent_uses_deterministic_fallback(snapshot, settings, scans):
    report, _ = _report(snapshot, settings, scans)
    assert report.summary.risk_source == "deterministic"
    assert report.summary.overall_risk == "critical"
    assert report.prioritized and all(p.ranked_by == "deterministic" for p in report.prioritized)
    # configuration critical on a running container ranks before the image CVE critical
    assert report.prioritized[0].finding_id.startswith("F-C008")
    assert report.summary.vulnerable_images == 1
    assert "AI analysis unavailable" in report.summary.executive_summary


def test_report_with_agent_prioritisation(snapshot, settings, scans):
    findings = rules.evaluate(snapshot, settings.rules)
    target = next(f for f in findings if f.rule_id == "N002" and f.resource_name == "router")
    assessment = AgentAssessment(
        executive_summary="Router bridges zones.",
        overall_risk="high",
        prioritized_findings=[PrioritizedItem(finding_id=target.id, rank=1, rationale="pivot")],
        potential_concerns=[],
        recommendations=["Split networks"],
        limitations=["none"],
    )
    validation = validate_agent_output(assessment, findings, snapshot, scans)
    report, _ = _report(snapshot, settings, scans, validation, agent_status="ok")
    assert report.summary.risk_source == "agent" and report.summary.overall_risk == "high"
    assert report.prioritized[0].finding_id == target.id
    assert report.prioritized[0].ranked_by == "agent"
    assert "Split networks" in report.recommendations


def test_markdown_has_all_sections_and_files_are_written(snapshot, settings, scans, tmp_path):
    report, findings = _report(snapshot, settings, scans)
    md = render_markdown(report)
    for heading in (
        "1. Assessment summary",
        "2. Docker environment overview",
        "3. Container inventory",
        "4. Image inventory",
        "5. Network configuration",
        "6. Prioritized findings",
        "7. Security misconfigurations",
        "8. Known image vulnerabilities",
        "9. Potential concerns",
        "10. Remediation recommendations",
        "11. Limitations and unknowns",
        "12. Model and execution metrics",
    ):
        assert f"## {heading}" in md, heading
    assert "CVE-2026-103111" in md
    json_path, md_path = write_report(report, tmp_path)
    assert Report.model_validate_json(json_path.read_text()).run_id == "run-x"
    assert md_path.read_text() == md
    # No secret values anywhere in the outputs.
    for secret in ("Sup3rS3cret!", "some-long-secret-you-generate", "hunter2"):
        assert secret not in json_path.read_text() and secret not in md


def test_old_database_is_migrated(tmp_path):
    import sqlite3

    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """CREATE TABLE schema_info (version INTEGER NOT NULL);
        INSERT INTO schema_info VALUES (1);
        CREATE TABLE runs (run_id TEXT PRIMARY KEY, started_at TEXT NOT NULL,
            finished_at TEXT, status TEXT NOT NULL, mode TEXT NOT NULL,
            objective TEXT NOT NULL, model_profile TEXT, model_provider TEXT,
            model_id TEXT, model_config_json TEXT, prompt_version TEXT,
            mcp_servers_json TEXT, snapshot_id TEXT, session_id TEXT,
            agent_status TEXT, errors_json TEXT, metrics_json TEXT, report_json TEXT);"""
    )
    conn.close()

    repo = AssessmentRepository(db)
    cols = {r["name"] for r in repo.conn.execute("PRAGMA table_info(runs)")}
    assert {"docker_endpoint_json", "manifest_sha256", "config_sha256", "manifest_json"} <= cols
    assert repo.conn.execute("SELECT version FROM schema_info").fetchone()[0] == SCHEMA_VERSION
    repo.close()
