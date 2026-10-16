"""Validate the LLM's structured output against the collected evidence.

LLMs - especially small local ones - can hallucinate CVE IDs, refer to
containers that do not exist, or "prioritise" finding IDs they made up. The
report must only contain evidence-grounded statements, so the agent's
``AgentAssessment`` is checked here before it is used:

* **Prioritised findings** must reference an existing confirmed finding ID.
  Unknown IDs are dropped (and noted).
* **Potential concerns** (new issues the model proposes) must
    - name a resource that exists in the inventory snapshot,
    - cite at least one verifiable evidence reference (a finding ID, a CVE
      from the scanner output, a resource name, or a docker-inspect field
      path that is present in the named resource's stored inspect data), and
    - not mention any CVE that Trivy did not report.
  Concerns that fail are kept in the report under "rejected agent claims"
  (transparency for model comparison) but never treated as findings.
* **Free text** (summary, recommendations, limitations): CVE IDs that are not
  in the scanner output are replaced with ``[unverified CVE removed]``.
* **Rationale consistency**: if a prioritisation rationale names containers
  but none of them is the finding's resource (or a container using the
  finding's image), the item is kept but flagged - small models sometimes
  attach the right text to the wrong finding ID.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from docker_security_agent.schemas.assets import InventorySnapshot
from docker_security_agent.schemas.findings import (
    Category,
    Confidence,
    Evidence,
    Finding,
    FindingSource,
    FindingStatus,
    Severity,
)
from docker_security_agent.schemas.observations import ImageScanResult
from docker_security_agent.schemas.reports import AgentAssessment, PrioritizedItem
from docker_security_agent.security.findings import finding_id

VULN_ID_RE = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})\b", re.I)
_INDEX_RE = re.compile(r"\[(\d+)\]")


@dataclass
class ValidationOutcome:
    assessment: AgentAssessment  # with unverified CVEs scrubbed from free text
    prioritized: list[PrioritizedItem] = field(default_factory=list)
    concerns: list[Finding] = field(default_factory=list)
    rejected: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _known_vuln_ids(scans: list[ImageScanResult]) -> set[str]:
    return {v.vuln_id.upper() for s in scans for v in s.vulnerabilities}


def _scrub_unknown_cves(text: str, known: set[str], notes: list[str], where: str) -> str:
    def replace(match: re.Match[str]) -> str:
        if match.group(0).upper() in known:
            return match.group(0)
        notes.append(f"{where}: removed {match.group(0)} (not present in scanner output)")
        return "[unverified CVE removed]"

    return VULN_ID_RE.sub(replace, text)


def _rationale_mismatch(text: str, finding: Finding, snapshot: InventorySnapshot) -> list[str]:
    """Container names mentioned in ``text`` when none of them matches ``finding``.

    Returns [] when the rationale mentions no container, or mentions a
    container that is the finding's resource / runs the finding's image.
    """
    mentioned = {
        c.name
        for c in snapshot.containers
        if re.search(rf"(?<![\w-]){re.escape(c.name)}(?![\w-])", text)
    }
    if not mentioned:
        return []
    allowed = {finding.resource_name}
    if finding.resource_type == "image":
        image_ids = {
            i.id for i in snapshot.images if finding.resource_name in (i.display_name, *i.tags)
        }
        allowed |= {c.name for c in snapshot.containers if c.image_id in image_ids}
    return [] if mentioned & allowed else sorted(mentioned)


def _inspect_docs(snapshot: InventorySnapshot, resource_name: str) -> list[dict]:
    """Raw (redacted) inspect documents of every asset matching ``resource_name``.

    Matches the same names/IDs as ``InventorySnapshot.resource_names``.
    Volumes have no stored inspect document, so they never match.
    """
    name = resource_name.strip().lstrip("/").lower()
    docs = []
    for c in snapshot.containers:
        if name in {c.name.lower(), c.id.lower(), c.id[:12].lower()}:
            docs.append(c.raw)
    for i in snapshot.images:
        if name in {n.lower() for n in (i.id, i.display_name, *i.tags, *i.digests)}:
            docs.append(i.raw)
    for n in snapshot.networks:
        if name in {n.name.lower(), n.id.lower(), n.id[:12].lower()}:
            docs.append(n.raw)
    return docs


def _path_exists(node: Any, parts: list[str]) -> bool:
    if not parts:
        return True
    if isinstance(node, dict):
        # Keys may contain dots themselves (labels such as com.docker.compose.project,
        # network names), so try every split, longest key first.
        for n in range(len(parts), 0, -1):
            key = ".".join(parts[:n])
            if key in node and _path_exists(node[key], parts[n:]):
                return True
        return False
    if isinstance(node, list):
        if parts[0].isdigit():
            i = int(parts[0])
            return i < len(node) and _path_exists(node[i], parts[1:])
        # No index (e.g. Mounts.Source): the path holds if any element has it.
        return any(_path_exists(item, parts) for item in node)
    return False


def inspect_path_exists(doc: dict, path: str) -> bool:
    """True if dotted ``path`` (e.g. ``HostConfig.CapAdd``, ``Mounts[0].Source``)
    is present in the inspect document ``doc``. Only key presence is checked,
    not whether the value supports the claim."""
    path = _INDEX_RE.sub(r".\1", path.strip()).lstrip(".")
    return bool(path) and _path_exists(doc, path.split("."))


def _category(value: str) -> Category:
    try:
        return Category(value.strip().lower())
    except ValueError:
        return Category.OTHER


def validate_agent_output(
    assessment: AgentAssessment,
    findings: list[Finding],
    snapshot: InventorySnapshot,
    scans: list[ImageScanResult],
) -> ValidationOutcome:
    known_findings = {f.id for f in findings}
    by_id = {f.id: f for f in findings}
    known_vulns = _known_vuln_ids(scans)
    resources = {r.lower() for r in snapshot.resource_names()}
    notes: list[str] = []

    # ---- free text: remove invented CVE IDs
    cleaned = assessment.model_copy(deep=True)
    cleaned.executive_summary = _scrub_unknown_cves(
        cleaned.executive_summary, known_vulns, notes, "executive_summary"
    )
    cleaned.recommendations = [
        _scrub_unknown_cves(r, known_vulns, notes, "recommendations")
        for r in cleaned.recommendations
    ]
    cleaned.limitations = [
        _scrub_unknown_cves(r, known_vulns, notes, "limitations") for r in cleaned.limitations
    ]

    outcome = ValidationOutcome(assessment=cleaned, notes=notes)

    # ---- prioritised findings must exist
    seen: set[str] = set()
    for item in sorted(assessment.prioritized_findings, key=lambda p: p.rank):
        if item.finding_id not in known_findings:
            notes.append(f"prioritized_findings: unknown finding id '{item.finding_id}' dropped")
            continue
        if item.finding_id in seen:
            continue
        seen.add(item.finding_id)
        item = item.model_copy()
        item.rationale = _scrub_unknown_cves(item.rationale, known_vulns, notes, "rationale")
        mismatch = _rationale_mismatch(item.rationale, by_id[item.finding_id], snapshot)
        if mismatch:
            notes.append(
                f"prioritized_findings: rationale for {item.finding_id} "
                f"({by_id[item.finding_id].resource_name}) talks about {', '.join(mismatch)}"
            )
        outcome.prioritized.append(item)

    # ---- potential concerns must be grounded
    for concern in assessment.potential_concerns:
        problems: list[str] = []
        resource_ok = concern.resource_name.lstrip("/").lower() in resources
        if not resource_ok:
            problems.append(f"resource '{concern.resource_name}' not found in the inventory")

        text = " ".join(
            [concern.title, concern.explanation, concern.remediation, *concern.evidence_refs]
        )
        unknown_cves = sorted({m.upper() for m in VULN_ID_RE.findall(text)} - known_vulns)
        if unknown_cves:
            problems.append(f"cites CVEs not in scanner output: {', '.join(unknown_cves)}")

        # Inspect paths must exist on the named resource itself, not just look plausible.
        docs = _inspect_docs(snapshot, concern.resource_name)
        valid_refs = []
        unverified_refs = []
        for ref in concern.evidence_refs:
            r = ref.strip()
            if (
                r in known_findings
                or r.upper() in known_vulns
                or r.lstrip("/").lower() in resources
                or any(inspect_path_exists(d, r) for d in docs)
            ):
                valid_refs.append(r)
            else:
                unverified_refs.append(r)
        if not valid_refs:
            problems.append("no verifiable evidence reference")

        strong = any(r in known_findings or r.upper() in known_vulns for r in valid_refs)
        # A rejected concern keeps every ref (what the model claimed); an accepted
        # one only carries the refs that checked out, the rest are noted.
        evidence_refs = concern.evidence_refs if problems else valid_refs
        notes_for_finding = list(problems)
        if not problems and unverified_refs:
            notes_for_finding.append(
                f"unverified evidence refs ignored: {', '.join(unverified_refs)}"
            )
        finding = Finding(
            id=finding_id("AGENT", concern.resource_name, concern.title),
            rule_id="AGENT",
            title=concern.title,
            resource_type="unknown",
            resource_name=concern.resource_name,
            category=_category(concern.category),
            severity=Severity(concern.severity),
            confidence=Confidence.MEDIUM if strong else Confidence.LOW,
            status=FindingStatus.REJECTED if problems else FindingStatus.POTENTIAL,
            source=FindingSource.AGENT,
            evidence=[
                Evidence(
                    source="agent", resource=concern.resource_name, path="evidence_ref", value=r
                )
                for r in evidence_refs
            ],
            explanation=concern.explanation,
            remediation=concern.remediation,
            validation_notes=notes_for_finding,
        )
        if problems:
            outcome.rejected.append(finding)
            notes.append(f"potential concern '{concern.title}' rejected: {'; '.join(problems)}")
        else:
            outcome.concerns.append(finding)

    return outcome
