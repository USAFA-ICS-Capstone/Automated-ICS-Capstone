"""Phase 2 (network verification): nmap target gate, claim extraction, report."""

from __future__ import annotations

from datetime import UTC, datetime

from docker_security_agent.mcp.policy import ToolPolicy
from docker_security_agent.reporting.verification_report import (
    build_verification_report,
    render_verification_markdown,
)
from docker_security_agent.schemas.reports import ModelInfo, RunMetrics
from docker_security_agent.schemas.verification import (
    VerificationAgentOutput,
    VerificationRecord,
    VerificationToolCall,
)
from docker_security_agent.agents.verification_tools import (
    VerificationCollector,
    verification_progress,
)
from docker_security_agent.verification_pipeline import network_claims


# --------------------------------------------------------------------------- policy


def test_nmap_allows_lab_host_and_subnet(settings):
    policy = ToolPolicy(settings.mcp)
    # lab hostname
    assert policy.check("nmap", "check_single_port", {"target": "plc", "port": 502}).allowed
    # IP inside the ICS subnet
    assert policy.check("nmap", "quick_scan", {"target": "192.168.95.10"}).allowed
    # IP inside the DMZ subnet
    assert policy.check("nmap", "service_scan", {"target": "192.168.90.5"}).allowed


def test_nmap_refuses_targets_off_the_range(settings):
    policy = ToolPolicy(settings.mcp)
    off_ip = policy.check("nmap", "quick_scan", {"target": "8.8.8.8"})
    assert not off_ip.allowed and "outside the lab subnets" in off_ip.reason
    off_host = policy.check("nmap", "check_single_port", {"target": "evil.example", "port": 80})
    assert not off_host.allowed
    assert not policy.check("nmap", "quick_scan", {"target": ""}).allowed


def test_modbus_reads_allowed_writes_not(settings):
    policy = ToolPolicy(settings.mcp)
    assert policy.check("modbus", "read_register", {"address": 0}).allowed
    assert policy.check("modbus", "read_input_registers", {"address": 0, "count": 1}).allowed
    # write tools are deliberately left out of the allow-list this pass
    assert not policy.check("modbus", "write_register", {"address": 0, "value": 1}).allowed


# --------------------------------------------------------------------------- claims


def test_network_claims_selects_only_network_findings():
    report = {
        "findings": [
            {
                "id": "F-AGENT-1",
                "title": "Elevated Network Capabilities",
                "resource_name": "plc",
                "explanation": "CAP_NET_ADMIN on the PLC",
                "evidence": [{"path": "HostConfig.CapAdd", "value": '["CAP_NET_ADMIN"]'}],
            },
            {
                "id": "F-AGENT-2",
                "title": "Exposed Web Service Port",
                "resource_name": "caldera",
                "explanation": "Port 8888 published",
                "evidence": [{"path": "NetworkSettings.Ports.8888/tcp", "value": "0.0.0.0:8888"}],
            },
            {
                "id": "F-AGENT-3",
                "title": "Running as Root User",
                "resource_name": "kali",
                "explanation": "Container runs as root",
                "evidence": [{"path": "Config.User", "value": "root"}],
            },
        ]
    }
    claims = network_claims(report)
    assert len(claims) == 2  # the root-user finding is not network-relevant
    joined = " ".join(claims)
    assert "F-AGENT-1" in joined and "F-AGENT-2" in joined
    assert "F-AGENT-3" not in joined
    # the claim carries the Phase-1 evidence so the verify agent knows what to test
    assert "CAP_NET_ADMIN" in joined


def test_network_claims_empty_report():
    assert network_claims({"findings": []}) == []
    assert network_claims({}) == []


# --------------------------------------------------------------------------- progress


def _rec(claim: str, fid: str = "") -> VerificationRecord:
    return VerificationRecord(
        claim=claim, source_finding_id=fid, verified="observed", assertion_type="observed",
        evidence="x", tool_calls=[], notes="",
    )


def test_progress_tracks_remaining_then_finalises():
    checklist = ["F-AGENT-1", "F-AGENT-2", "F-AGENT-3"]
    c = VerificationCollector()

    c.add(_rec("port on plc", "F-AGENT-1"))
    msg = verification_progress(c, checklist)
    assert "1 of 3" in msg and "F-AGENT-2" in msg and "F-AGENT-3" in msg

    # an id mentioned only in the claim text also counts as covered
    c.add(_rec("exposed port [F-AGENT-2] on caldera"))
    c.add(_rec("cap_net on kali", "F-AGENT-3"))
    done = verification_progress(c, checklist)
    assert "All 3" in done
    # the finalise message must steer the model to a summary-only answer
    assert "executive_summary" in done and "automatically" in done


# --------------------------------------------------------------------------- report


def _metrics() -> RunMetrics:
    return RunMetrics(started_at=datetime.now(UTC), finished_at=datetime.now(UTC))


def test_build_and_render_verification_report():
    record = VerificationRecord(
        claim="[F-AGENT-1] kali -> plc:502 reachable",
        source_finding_id="F-AGENT-1",
        verified="observed",
        assertion_type="observed",
        evidence="502/tcp open; read holding register 0 = 17342",
        tool_calls=[
            VerificationToolCall(
                tool="nmap.check_single_port",
                arguments="target=plc port=502",
                result="502/tcp open",
            ),
            VerificationToolCall(
                tool="modbus.read_register",
                arguments="address=0",
                result="17342",
            ),
        ],
        notes="",
    )
    report = build_verification_report(
        run_id="run-20261110-000000-test",
        model=ModelInfo(profile="local-qwen", provider="vllm", model="qwen3-32b"),
        source_report="outputs/run-20261110-000000-test/agent_report.json",
        agent_status="ok",
        output=VerificationAgentOutput(
            executive_summary="kali can reach plc:502 and a real Modbus device answered.",
            limitations=["Only the PLC was reachable to test."],
        ),
        records=[record],
        errors=[],
        metrics=_metrics(),
    )
    assert report.phase == "network-verification"
    assert len(report.verification) == 1

    md = render_verification_markdown(report, [])
    assert "Phase 2 — Network Verification" in md
    assert "## 2. Verification" in md
    assert "kali -> plc:502 reachable" in md
    assert "nmap.check_single_port" in md and "modbus.read_register" in md
    assert "`observed`" in md


def test_report_without_agent_output_is_safe():
    report = build_verification_report(
        run_id="run-x",
        model=ModelInfo(profile="p", provider="vllm", model="m"),
        source_report="outputs/run-x/agent_report.json",
        agent_status="timeout",
        output=None,
        records=[],
        errors=["agent: timed out"],
        metrics=_metrics(),
    )
    assert "no valid summary" in report.executive_summary
    md = render_verification_markdown(report, [])
    assert "_No claims were recorded._" in md
