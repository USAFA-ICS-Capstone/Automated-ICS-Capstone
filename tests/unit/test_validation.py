"""Validation of the LLM's structured output against evidence."""

from datetime import UTC, datetime

import grfics
import pytest

from docker_security_agent.schemas.findings import Confidence, FindingStatus
from docker_security_agent.schemas.observations import ImageScanResult
from docker_security_agent.schemas.reports import AgentAssessment, PotentialConcern, PrioritizedItem
from docker_security_agent.security import rules
from docker_security_agent.security.validation import inspect_path_exists, validate_agent_output
from docker_security_agent.security.vulnerability_parser import parse_findings_page


@pytest.fixture
def evidence(snapshot, settings):
    findings = rules.evaluate(snapshot, settings.rules)
    vulns = parse_findings_page(grfics.trivy_findings_page(None, 10))[0]
    image = next(i for i in snapshot.images if i.tags == ["fortiphyd/grfics-plc:latest"])
    scan = ImageScanResult(
        image_id=image.id,
        image_ref=image.tags[0],
        scanned_at=datetime.now(UTC),
        vulnerabilities=vulns,
    )
    return findings, [scan]


def _assessment(**overrides):
    base = dict(
        executive_summary="Risky.",
        overall_risk="high",
        prioritized_findings=[],
        potential_concerns=[],
        recommendations=[],
        limitations=[],
    )
    base.update(overrides)
    return AgentAssessment(**base)


def test_unknown_finding_ids_are_dropped(snapshot, evidence):
    findings, scans = evidence
    real = next(f for f in findings if f.rule_id == "C008")
    a = _assessment(
        prioritized_findings=[
            PrioritizedItem(finding_id="F-FAKE-123", rank=1, rationale="made up"),
            PrioritizedItem(finding_id=real.id, rank=2, rationale="socket"),
            PrioritizedItem(finding_id=real.id, rank=3, rationale="duplicate"),
        ]
    )
    out = validate_agent_output(a, findings, snapshot, scans)
    assert [p.finding_id for p in out.prioritized] == [real.id]
    assert any("F-FAKE-123" in n for n in out.notes)


def test_invented_cves_are_scrubbed_from_text(snapshot, evidence):
    findings, scans = evidence
    a = _assessment(
        executive_summary="See CVE-2026-103111 and CVE-1999-0001.",
        recommendations=["Patch CVE-2021-44228 now"],
    )
    out = validate_agent_output(a, findings, snapshot, scans)
    assert "CVE-2026-103111" in out.assessment.executive_summary  # real (from scanner)
    assert "CVE-1999-0001" not in out.assessment.executive_summary
    assert "[unverified CVE removed]" in out.assessment.recommendations[0]


def test_potential_concerns_are_grounded_or_rejected(snapshot, evidence):
    findings, scans = evidence
    socket = next(f for f in findings if f.rule_id == "C008")
    good = PotentialConcern(
        title="Socket + published port on simulation",
        resource_name="simulation",
        category="filesystem",
        severity="critical",
        explanation="x",
        remediation="y",
        evidence_refs=[socket.id, "HostConfig.PortBindings"],
    )
    ghost = PotentialConcern(
        title="Ghost container",
        resource_name="does-not-exist",
        category="privilege",
        severity="high",
        explanation="x",
        remediation="y",
        evidence_refs=[socket.id],
    )
    fake_cve = PotentialConcern(
        title="Log4Shell",
        resource_name="plc",
        category="image-vulnerability",
        severity="critical",
        explanation="CVE-2021-44228 in plc",
        remediation="y",
        evidence_refs=["CVE-2021-44228"],
    )
    no_evidence = PotentialConcern(
        title="Vague",
        resource_name="plc",
        category="other",
        severity="low",
        explanation="x",
        remediation="y",
        evidence_refs=["I just feel it"],
    )
    out = validate_agent_output(
        _assessment(potential_concerns=[good, ghost, fake_cve, no_evidence]),
        findings,
        snapshot,
        scans,
    )
    assert [c.title for c in out.concerns] == [good.title]
    assert out.concerns[0].status == FindingStatus.POTENTIAL
    rejected = {c.title: c for c in out.rejected}
    assert set(rejected) == {"Ghost container", "Log4Shell", "Vague"}
    assert all(c.status == FindingStatus.REJECTED for c in out.rejected)
    assert "not found in the inventory" in rejected["Ghost container"].validation_notes[0]
    assert "CVE-2021-44228" in " ".join(rejected["Log4Shell"].validation_notes)


def test_rationale_naming_a_different_container_is_flagged(snapshot, evidence):
    findings, scans = evidence
    socket = next(f for f in findings if f.rule_id == "C008")  # resource: simulation
    plc_image = next(
        f
        for f in findings
        if f.rule_id == "I001" and f.resource_name == "fortiphyd/grfics-plc:latest"
    )
    a = _assessment(
        prioritized_findings=[
            PrioritizedItem(finding_id=socket.id, rank=1, rationale="router forwards traffic"),
            PrioritizedItem(finding_id=plc_image.id, rank=2, rationale="the plc image floats"),
            PrioritizedItem(finding_id=socket.id + "x", rank=3, rationale="unknown"),
        ]
    )
    out = validate_agent_output(a, findings, snapshot, scans)
    flagged = [n for n in out.notes if "talks about" in n]
    assert len(flagged) == 1 and "router" in flagged[0] and socket.id in flagged[0]
    # flagged items are kept (the finding itself is real), only annotated
    assert [p.finding_id for p in out.prioritized] == [socket.id, plc_image.id]


def _concern(resource_name, *refs, title="Concern"):
    return PotentialConcern(
        title=title,
        resource_name=resource_name,
        category="other",
        severity="medium",
        explanation="x",
        remediation="y",
        evidence_refs=list(refs),
    )


@pytest.mark.parametrize(
    "ref",
    [
        "HostConfig.ThisFieldDoesNotExist",  # right section prefix, invented field
        "Config.Totally.Made.Up",
        "RepoTags",  # real image field, but plc is a container
    ],
)
def test_inspect_path_must_exist_on_the_named_resource(snapshot, evidence, ref):
    findings, scans = evidence
    out = validate_agent_output(
        _assessment(potential_concerns=[_concern("plc", ref)]), findings, snapshot, scans
    )
    assert out.concerns == []
    assert out.rejected[0].status == FindingStatus.REJECTED
    assert "no verifiable evidence reference" in out.rejected[0].validation_notes


@pytest.mark.parametrize(
    ("resource", "ref"),
    [
        ("plc", "HostConfig.PortBindings"),
        ("/plc", "Config.Labels.com.docker.compose.service"),  # dotted key
        ("plc", "Mounts[0].Source"),
        ("fortiphyd/grfics-plc:latest", "RepoTags"),
        ("b-ics-net", "IPAM"),
    ],
)
def test_existing_inspect_path_is_accepted(snapshot, evidence, resource, ref):
    findings, scans = evidence
    out = validate_agent_output(
        _assessment(potential_concerns=[_concern(resource, ref)]), findings, snapshot, scans
    )
    assert [c.status for c in out.concerns] == [FindingStatus.POTENTIAL]
    assert out.concerns[0].confidence == Confidence.LOW  # an inspect path is weak evidence
    assert out.rejected == []


def test_unverified_refs_are_dropped_from_an_accepted_concern(snapshot, evidence):
    findings, scans = evidence
    socket = next(f for f in findings if f.rule_id == "C008")  # resource: simulation
    out = validate_agent_output(
        _assessment(
            potential_concerns=[_concern("simulation", socket.id, "HostConfig.NotARealField")]
        ),
        findings,
        snapshot,
        scans,
    )
    [concern] = out.concerns
    assert [e.value for e in concern.evidence] == [socket.id]
    assert concern.validation_notes == [
        "unverified evidence refs ignored: HostConfig.NotARealField"
    ]


def test_inspect_path_exists():
    doc = {
        "HostConfig": {"CapAdd": None, "Binds": ["/a:/b"]},
        "Config": {"Labels": {"com.docker.compose.project": "grfics"}},
        "Mounts": [{"Source": "/a"}, {"Source": "/b", "RW": True}],
    }
    assert inspect_path_exists(doc, "HostConfig.CapAdd")  # present even when null
    assert inspect_path_exists(doc, "Config.Labels.com.docker.compose.project")
    assert inspect_path_exists(doc, "Mounts.1.RW")
    assert inspect_path_exists(doc, "Mounts[1].RW")
    assert inspect_path_exists(doc, ".Mounts.RW")  # unindexed: any element
    assert not inspect_path_exists(doc, "Mounts[0].RW")
    assert not inspect_path_exists(doc, "Mounts[5]")
    assert not inspect_path_exists(doc, "HostConfig.CapAdd.NET_ADMIN")  # cannot descend into null
    assert not inspect_path_exists(doc, "HostConfig.Privileged")
    assert not inspect_path_exists(doc, "")
