"""Trivy result parsing and vulnerability findings."""

from datetime import UTC, datetime

import grfics

from docker_security_agent.schemas.findings import FindingSource, Severity
from docker_security_agent.schemas.observations import ImageScanResult
from docker_security_agent.security.vulnerability_parser import (
    count_by_severity,
    parse_findings_page,
    parse_scan_summary,
    vulnerability_findings,
)


def _scan(snapshot, vulns, status="ok"):
    image = next(i for i in snapshot.images if i.tags == ["fortiphyd/grfics-plc:latest"])
    return ImageScanResult(
        image_id=image.id,
        image_ref=image.tags[0],
        digest=image.digest,
        scanner_version="0.68.2",
        status=status,
        scanned_at=datetime.now(UTC),
        counts=count_by_severity(vulns),
        vulnerabilities=vulns,
    )


def test_parse_scan_summary():
    batch, counts = parse_scan_summary(grfics.trivy_scan_summary("img"))
    assert batch == "batch-1"
    assert counts == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1}


def test_parse_findings_pages_verbatim():
    page1, token = parse_findings_page(grfics.trivy_findings_page(None))
    page2, token2 = parse_findings_page(grfics.trivy_findings_page(token))
    assert token == "2" and token2 is None
    vulns = page1 + page2
    assert [v.vuln_id for v in vulns] == [
        "CVE-2026-103111",
        "CVE-2026-14456",
        "GHSA-abcd-efgh-ijkl",
    ]
    assert vulns[0].severity == "CRITICAL" and vulns[0].fixed_version == "10.49-r0"
    assert vulns[2].has_fix is False and vulns[2].fixed_version == ""


def test_non_vulnerability_categories_ignored():
    page = {"findings": [{"i": "x", "c": 3, "s": 4, "id": "aws-access-key"}], "next_token": ""}
    assert parse_findings_page(page)[0] == []


def test_vulnerability_finding_per_image(snapshot):
    vulns = parse_findings_page(grfics.trivy_findings_page(None, page_size=10))[0]
    findings = vulnerability_findings([_scan(snapshot, vulns)], snapshot)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "V001" and f.source == FindingSource.SCANNER
    assert f.severity == Severity.CRITICAL  # highest severity present
    assert f.resource_name == "fortiphyd/grfics-plc:latest"
    assert "plc" in f.explanation  # used-by containers
    cited = " ".join(e.value for e in f.evidence)
    assert "CVE-2026-103111" in cited and "fixed=10.49-r0" in cited


def test_no_findings_for_clean_or_failed_scans(snapshot):
    assert vulnerability_findings([_scan(snapshot, [])], snapshot) == []
    assert vulnerability_findings([_scan(snapshot, [], status="error")], snapshot) == []


def test_min_severity_threshold(snapshot):
    vulns = [
        v
        for v in parse_findings_page(grfics.trivy_findings_page(None, 10))[0]
        if v.severity == "MEDIUM"
    ]
    assert vulnerability_findings([_scan(snapshot, vulns)], snapshot, "high") == []
    assert vulnerability_findings([_scan(snapshot, vulns)], snapshot, "low")
