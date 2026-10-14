"""Helpers for building findings consistently.

Finding IDs are *deterministic*: ``F-<rule>-<hash>`` where the hash covers the
rule, the resource and the specific detail (e.g. which capability). The same
misconfiguration therefore keeps the same ID across runs and across models,
which is what lets you compare "did model A and model B both prioritise
F-C008-...?" and track whether an issue was fixed between assessments.
"""

from __future__ import annotations

import hashlib

from docker_security_agent.schemas.findings import (
    Category,
    Confidence,
    Evidence,
    Finding,
    FindingSource,
    FindingStatus,
    Severity,
)


def finding_id(rule_id: str, resource: str, detail: str = "") -> str:
    digest = hashlib.sha1(f"{rule_id}|{resource}|{detail}".encode()).hexdigest()[:10]
    return f"F-{rule_id}-{digest}"


def make_finding(
    *,
    rule_id: str,
    title: str,
    resource_type: str,
    resource_name: str,
    resource_id: str = "",
    category: Category,
    severity: Severity,
    confidence: Confidence = Confidence.HIGH,
    evidence: list[Evidence],
    explanation: str,
    remediation: str,
    detail: str = "",
    source: FindingSource = FindingSource.RULE,
    references: list[str] | None = None,
) -> Finding:
    """Create a *confirmed* finding (rules and scanner output are facts)."""
    return Finding(
        id=finding_id(rule_id, resource_id or resource_name, detail),
        rule_id=rule_id,
        title=title,
        resource_type=resource_type,
        resource_name=resource_name,
        resource_id=resource_id,
        category=category,
        severity=severity,
        confidence=confidence,
        status=FindingStatus.CONFIRMED,
        source=source,
        evidence=evidence,
        explanation=explanation,
        remediation=remediation,
        references=references or [],
    )


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts
