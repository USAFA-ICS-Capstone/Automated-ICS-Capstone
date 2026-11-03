"""Unit tests for NmapNetworkAgent — no network, no nmap, no LLM required.

Covers:
  - build_nmap_input: message formatting
  - _parse_assessment_text: JSON extraction from raw model output (fence / bare / think-block)
  - build_nmap_agent: native vs prompted mode selection
  - NmapAgentRunOutcome: _usage_of handles missing/partial usage objects
  - Schema helpers: NmapHost.ics_ports, NmapScan.ics_hits / all_ports
  - ICS_PORTS / IT_PORTS: no duplicates, port numbers are valid
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from agents import Model, ModelSettings

from docker_security_agent.agents.nmap_network_agent import (
    ICS_PORTS,
    IT_PORTS,
    _parse_assessment_text,
    _usage_of,
    build_nmap_agent,
    build_nmap_input,
    build_nmap_input_from_docker_context,
    docker_scan_targets,
)
from docker_security_agent.config import ModelProfile
from docker_security_agent.llm.factory import ModelBundle
from docker_security_agent.schemas.nmap_network import (
    ExposedICSService,
    NetworkFinding,
    NmapHost,
    NmapNetworkAssessment,
    NmapPort,
    NmapScan,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MINIMAL_ASSESSMENT = {
    "executive_summary": "Test summary.",
    "overall_risk": "high",
    "hosts_assessed": ["192.168.95.10"],
    "exposed_ics_services": [
        {
            "host": "192.168.95.10",
            "port": 502,
            "protocol_name": "Modbus TCP",
            "risk_level": "high",
            "rationale": "Unauthenticated Modbus on the ICS network.",
            "recommended_action": "Restrict port 502 to authorised engineering workstations.",
        }
    ],
    "findings": [
        {
            "title": "Modbus TCP exposed",
            "severity": "high",
            "host": "192.168.95.10",
            "port": 502,
            "evidence": "Nmap: 502/tcp open modbus",
            "recommendation": "Firewall port 502.",
        }
    ],
    "attack_surface_summary": "One host with Modbus exposed.",
    "recommendations": ["Restrict ICS ports to authorised subnets."],
    "limitations": ["Only the target /24 was scanned."],
}


def _assessment_json(**overrides) -> str:
    doc = {**MINIMAL_ASSESSMENT, **overrides}
    return json.dumps(doc)


def _make_bundle(structured_output: str = "native") -> ModelBundle:
    profile = ModelProfile(
        name="test-model",
        provider="openai",
        model="gpt-4o-mini",
        base_url="http://unused/v1",
        structured_output=structured_output,
        temperature=0.0,
    )
    model_mock = MagicMock(spec=Model)
    return ModelBundle(model=model_mock, settings=ModelSettings(), profile=profile)


# ---------------------------------------------------------------------------
# build_nmap_input
# ---------------------------------------------------------------------------


class TestBuildNmapInput:
    def test_single_target_appears_in_output(self):
        msg = build_nmap_input(["192.168.95.0/24"])
        assert "192.168.95.0/24" in msg

    def test_multiple_targets_all_appear(self):
        targets = ["10.0.0.1", "192.168.1.0/24", "172.16.0.5"]
        msg = build_nmap_input(targets)
        for t in targets:
            assert t in msg

    def test_target_count_is_reported(self):
        msg = build_nmap_input(["a", "b", "c"])
        assert "TARGETS (3)" in msg

    def test_default_objective_is_included(self):
        msg = build_nmap_input(["10.0.0.1"])
        assert "OBJECTIVE:" in msg
        assert "ICS" in msg  # default objective mentions ICS

    def test_custom_objective_replaces_default(self):
        msg = build_nmap_input(["10.0.0.1"], objective="Find all Modbus devices.")
        assert "Find all Modbus devices." in msg
        # Default objective text should NOT appear
        assert "ICS-aware network reconnaissance" not in msg

    def test_empty_target_list_produces_zero_count(self):
        msg = build_nmap_input([])
        assert "TARGETS (0)" in msg

    def test_output_is_string(self):
        assert isinstance(build_nmap_input(["127.0.0.1"]), str)

    def test_do_nmap_instruction_is_present(self):
        msg = build_nmap_input(["10.0.0.0/8"])
        assert "do-nmap" in msg


# ---------------------------------------------------------------------------
# _parse_assessment_text
# ---------------------------------------------------------------------------


class TestParseAssessmentText:
    """_parse_assessment_text must handle all the messy formats a model can emit."""

    def test_bare_json_parses(self):
        result = _parse_assessment_text(_assessment_json())
        assert isinstance(result, NmapNetworkAssessment)
        assert result.overall_risk == "high"

    def test_json_code_fence_parses(self):
        raw = f"```json\n{_assessment_json()}\n```"
        result = _parse_assessment_text(raw)
        assert result.overall_risk == "high"

    def test_plain_code_fence_parses(self):
        raw = f"```\n{_assessment_json()}\n```"
        result = _parse_assessment_text(raw)
        assert result.overall_risk == "high"

    def test_think_block_is_stripped_before_parsing(self):
        think = "<think>Let me reason about this carefully...</think>"
        raw = f"{think}\n{_assessment_json()}"
        result = _parse_assessment_text(raw)
        assert result.overall_risk == "high"

    def test_think_block_with_fence_parses(self):
        think = "<think>Multi-line\nreasoning block\nhere.</think>"
        raw = f"{think}\n```json\n{_assessment_json()}\n```"
        result = _parse_assessment_text(raw)
        assert result.executive_summary == "Test summary."

    def test_prose_prefix_and_suffix_are_ignored(self):
        raw = f"Here is the assessment:\n{_assessment_json()}\nThat concludes the report."
        result = _parse_assessment_text(raw)
        assert result.overall_risk == "high"

    def test_empty_string_raises(self):
        with pytest.raises((ValueError, Exception)):
            _parse_assessment_text("")

    def test_no_json_raises(self):
        with pytest.raises((ValueError, Exception)):
            _parse_assessment_text("Sorry, I cannot complete this task.")

    def test_invalid_schema_raises_validation_error(self):
        bad = json.dumps({"executive_summary": "ok"})  # missing required fields
        with pytest.raises(Exception):
            _parse_assessment_text(bad)

    def test_ics_services_are_preserved(self):
        result = _parse_assessment_text(_assessment_json())
        assert len(result.exposed_ics_services) == 1
        assert result.exposed_ics_services[0].port == 502

    def test_findings_are_preserved(self):
        result = _parse_assessment_text(_assessment_json())
        assert len(result.findings) == 1
        assert result.findings[0].severity == "high"

    def test_critical_risk_level_accepted(self):
        result = _parse_assessment_text(_assessment_json(overall_risk="critical"))
        assert result.overall_risk == "critical"

    def test_low_risk_level_accepted(self):
        result = _parse_assessment_text(_assessment_json(overall_risk="low"))
        assert result.overall_risk == "low"


# ---------------------------------------------------------------------------
# _usage_of
# ---------------------------------------------------------------------------


class TestUsageOf:
    def test_returns_dict_for_valid_usage(self):
        ctx = SimpleNamespace(
            usage=SimpleNamespace(requests=1, input_tokens=100, output_tokens=50, total_tokens=150)
        )
        result = _usage_of(ctx)
        assert result == {
            "requests": 1,
            "input_tokens": 100,
            "output_tokens": 50,
            "total_tokens": 150,
        }

    def test_returns_empty_dict_when_usage_is_none(self):
        ctx = SimpleNamespace(usage=None)
        assert _usage_of(ctx) == {}

    def test_returns_empty_dict_when_attribute_missing(self):
        ctx = SimpleNamespace()  # no `usage` attribute at all
        assert _usage_of(ctx) == {}


# ---------------------------------------------------------------------------
# build_nmap_agent
# ---------------------------------------------------------------------------


class TestBuildNmapAgent:
    def test_native_mode_uses_output_type(self):
        bundle = _make_bundle(structured_output="native")
        agent = build_nmap_agent(bundle, mcp_servers=[])
        assert agent.output_type is NmapNetworkAssessment

    def test_prompted_mode_output_type_is_none(self):
        bundle = _make_bundle(structured_output="prompted")
        agent = build_nmap_agent(bundle, mcp_servers=[])
        assert agent.output_type is None

    def test_prompted_mode_injects_schema_into_instructions(self):
        bundle = _make_bundle(structured_output="prompted")
        agent = build_nmap_agent(bundle, mcp_servers=[])
        assert "JSON schema" in agent.instructions or "json_schema" in agent.instructions.lower() or "schema" in agent.instructions.lower()

    def test_agent_has_no_local_function_tools(self):
        """NmapNetworkAgent must drive nmap via MCP only, never local tools."""
        bundle = _make_bundle()
        agent = build_nmap_agent(bundle, mcp_servers=[])
        assert agent.tools == []

    def test_agent_name_is_correct(self):
        bundle = _make_bundle()
        agent = build_nmap_agent(bundle, mcp_servers=[])
        assert agent.name == "NmapNetworkAgent"

    def test_ics_safe_flags_are_in_instructions(self):
        bundle = _make_bundle()
        agent = build_nmap_agent(bundle, mcp_servers=[])
        assert "-sT" in agent.instructions
        assert "-T2" in agent.instructions

    def test_dangerous_flags_are_prohibited_in_instructions(self):
        bundle = _make_bundle()
        agent = build_nmap_agent(bundle, mcp_servers=[])
        # The instructions must warn against aggressive timing
        assert "-T3" in agent.instructions or "T3" in agent.instructions


# ---------------------------------------------------------------------------
# Port list sanity
# ---------------------------------------------------------------------------


class TestPortLists:
    def test_ics_ports_have_no_duplicates(self):
        port_nums = [int(p) for p, _ in ICS_PORTS]
        assert len(port_nums) == len(set(port_nums))

    def test_it_ports_have_no_duplicates(self):
        port_nums = [int(p) for p, _ in IT_PORTS]
        assert len(port_nums) == len(set(port_nums))

    def test_ics_and_it_ports_do_not_overlap(self):
        ics = {int(p) for p, _ in ICS_PORTS}
        it = {int(p) for p, _ in IT_PORTS}
        assert ics.isdisjoint(it), f"Overlapping ports: {ics & it}"

    def test_port_numbers_are_valid(self):
        for port, _ in ICS_PORTS + IT_PORTS:
            n = int(port)
            assert 1 <= n <= 65535

    def test_known_ics_protocols_are_listed(self):
        ports = {int(p) for p, _ in ICS_PORTS}
        assert 502 in ports   # Modbus
        assert 102 in ports   # S7comm
        assert 44818 in ports # EtherNet/IP
        assert 4840 in ports  # OPC UA
        assert 20000 in ports # DNP3

    def test_known_it_protocols_are_listed(self):
        ports = {int(p) for p, _ in IT_PORTS}
        assert 22 in ports    # SSH
        assert 80 in ports    # HTTP
        assert 443 in ports   # HTTPS
        assert 23 in ports    # Telnet


# ---------------------------------------------------------------------------
# Schema: NmapHost and NmapScan helpers
# ---------------------------------------------------------------------------


class TestNmapSchemaHelpers:
    def _make_host(self, open_ports: list[int]) -> NmapHost:
        return NmapHost(
            address="192.168.95.10",
            ports=[NmapPort(port=p) for p in open_ports],
        )

    def test_ics_ports_filters_known_ics_port(self):
        host = self._make_host([22, 502, 80])
        ics = host.ics_ports
        assert len(ics) == 1
        assert ics[0].port == 502

    def test_ics_ports_empty_for_it_only_host(self):
        host = self._make_host([22, 80, 443])
        assert host.ics_ports == []

    def test_ics_ports_returns_multiple_ics_ports(self):
        host = self._make_host([102, 502, 4840, 44818])
        assert len(host.ics_ports) == 4

    def test_nmap_scan_all_ports_is_flat(self):
        h1 = self._make_host([22, 80])
        h2 = self._make_host([502])
        scan = NmapScan(target="192.168.95.0/24", hosts=[h1, h2])
        pairs = scan.all_ports
        assert len(pairs) == 3
        assert all(isinstance(addr, str) and isinstance(port, NmapPort) for addr, port in pairs)

    def test_nmap_scan_ics_hits_only_includes_ics(self):
        h1 = self._make_host([22, 502])  # one ICS port
        h2 = self._make_host([80, 443])  # no ICS ports
        scan = NmapScan(target="192.168.95.0/24", hosts=[h1, h2])
        hits = scan.ics_hits
        assert len(hits) == 1
        assert hits[0][1].port == 502

    def test_nmap_scan_empty_hosts(self):
        scan = NmapScan(target="10.0.0.1")
        assert scan.all_ports == []
        assert scan.ics_hits == []

    def test_nmap_assessment_validates_full_structure(self):
        assessment = NmapNetworkAssessment(**MINIMAL_ASSESSMENT)
        assert assessment.overall_risk == "high"
        assert len(assessment.exposed_ics_services) == 1
        assert len(assessment.findings) == 1

    def test_network_finding_port_is_optional(self):
        finding = NetworkFinding(
            title="No open ports found",
            severity="info",
            host="192.168.95.99",
            port=None,
            evidence="Nmap: 0 hosts up",
            recommendation="No action needed.",
        )
        assert finding.port is None

    def test_exposed_ics_service_risk_levels(self):
        for level in ("critical", "high", "medium", "low"):
            svc = ExposedICSService(
                host="10.0.0.1",
                port=502,
                protocol_name="Modbus",
                risk_level=level,
                rationale="test",
                recommended_action="test",
            )
            assert svc.risk_level == level


# ---------------------------------------------------------------------------
# build_nmap_input_from_docker_context / docker_scan_targets
# ---------------------------------------------------------------------------


def _docker_finding(resource: str, title: str, severity: str) -> dict:
    return {
        "title": title,
        "resource_name": resource,
        "severity": severity,
        "evidence": [],
        "vulnerability_ids": [],
        "explanation": "x",
        "remediation": "y",
    }


def _docker_assessment(*findings):
    from docker_security_agent.schemas.reports import AgentAssessment

    return AgentAssessment(
        executive_summary="x",
        overall_risk="critical",
        findings=list(findings),
        recommendations=[],
        limitations=[],
    )


def _section(text: str, header: str) -> str:
    """The lines of one input section, up to the next blank line."""
    start = text.index(header)
    end = text.find("\n\n", start)
    return text[start : end if end != -1 else None]


class TestDockerContextInput:
    def test_targets_are_running_in_scope_container_ips(self, snapshot, settings):
        targets = docker_scan_targets(snapshot, settings.rules.ignore_containers)
        running = {
            ip
            for c in snapshot.containers
            if c.running
            for ip in c.ip_addresses.values()
        }
        assert set(targets) == running
        assert "172.17.0.9" not in targets  # bad-debug is exited
        # numeric, not lexical, order: .2 before .45 before .200
        ics = [t for t in targets if t.startswith("192.168.95.")]
        assert ics == sorted(ics, key=lambda ip: int(ip.rsplit(".", 1)[1]))

    def test_ignored_containers_are_not_targets(self, snapshot):
        plc_ips = set(snapshot.container_by_name("plc").ip_addresses.values())
        targets = docker_scan_targets(snapshot, ["pl*"])
        assert plc_ips and not plc_ips & set(targets)

    def test_subnets_are_context_not_targets(self, snapshot, settings):
        text = build_nmap_input_from_docker_context(
            snapshot, None, ignored_containers=settings.rules.ignore_containers
        )
        targets = _section(text, "TARGETS")
        assert "/24" not in targets and "/16" not in targets
        assert "b-ics-net: 192.168.95.0/24" in _section(text, "DOCKER NETWORKS")
        # the default bridge (/16) only holds the exited container -> not listed
        assert "172.17.0.0/16" not in text

    def test_high_severity_containers_are_prioritised(self, snapshot, settings):
        assessment = _docker_assessment(
            _docker_finding("simulation", "Docker socket mounted", "critical"),
            _docker_finding("router", "NET_ADMIN capability", "high"),
            _docker_finding("plc", "Runs as root", "medium"),
            _docker_finding("bad-debug", "Privileged", "critical"),  # exited
            _docker_finding("ghost", "Invented container", "high"),  # not in inventory
        )
        text = build_nmap_input_from_docker_context(
            snapshot, assessment, ignored_containers=settings.rules.ignore_containers
        )
        priority = _section(text, "PRIORITY TARGETS")
        assert "* simulation (172.30.0.2, 192.168.95.45)" in priority
        assert "[CRITICAL] Docker socket mounted" in priority
        assert "* router" in priority and "[HIGH] NET_ADMIN capability" in priority
        for absent in ("plc", "bad-debug", "ghost", "Runs as root"):
            assert absent not in priority

    def test_findings_sorted_and_capped_per_container(self, snapshot, settings):
        findings = [_docker_finding("simulation", f"high-{i}", "high") for i in range(6)]
        findings.append(_docker_finding("simulation", "the-critical-one", "critical"))
        text = build_nmap_input_from_docker_context(
            snapshot,
            _docker_assessment(*findings),
            ignored_containers=settings.rules.ignore_containers,
        )
        priority = _section(text, "PRIORITY TARGETS")
        bullets = [ln for ln in priority.splitlines() if ln.startswith("      - ")]
        assert bullets[0].endswith("[CRITICAL] the-critical-one")
        assert len(bullets) == 6 and bullets[-1].endswith("... and 2 more")

    def test_no_assessment_still_lists_all_targets(self, snapshot, settings):
        text = build_nmap_input_from_docker_context(
            snapshot, None, ignored_containers=settings.rules.ignore_containers
        )
        assert "PRIORITY TARGETS" not in text
        assert "did not produce results" in text
        ignored = settings.rules.ignore_containers
        assert f"TARGETS ({len(docker_scan_targets(snapshot, ignored))})" in text

    def test_published_and_extra_ports(self, snapshot, settings):
        text = build_nmap_input_from_docker_context(
            snapshot, None, ignored_containers=settings.rules.ignore_containers
        )
        published = _section(text, "PORTS PUBLISHED")
        assert "hardened: 8443/tcp -> host 127.0.0.1:8443" in published
        assert "simulation: 80/tcp -> host all interfaces:80" in published
        extra = _section(text, "ADDITIONAL PORTS")
        # only TCP container ports not already in the ICS/IT lists
        assert "6080" in extra and "8888" in extra
        assert "8080" not in extra and "51820" not in extra  # known / UDP

    def test_docker_findings_marked_as_context_only(self, snapshot):
        text = build_nmap_input_from_docker_context(snapshot, _docker_assessment())
        assert "grounded in do-nmap output" in text
        assert "do not copy Docker findings" in text
