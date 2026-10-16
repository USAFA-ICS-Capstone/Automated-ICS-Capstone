"""Report models.

Two families live here:

1. ``AgentAssessment`` - the structured output the LLM must return. It is kept
   deliberately simple (only required fields, no dicts, no defaults) because
   strict JSON-schema mode at OpenAI, and many local models, cope badly with
   optional/complex schemas.

2. ``Report`` - the final report written to ``report.json`` and rendered to
   ``report.md``. It combines deterministic findings, scanner results, the
   (validated) agent analysis and run metrics.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from docker_security_agent.schemas.findings import Finding

# ---------------------------------------------------------------------------
# 1. What the LLM returns
# ---------------------------------------------------------------------------


class PrioritizedItem(BaseModel):
    """The agent's ranking of an EXISTING confirmed finding."""

    # NOTE: no example ID in the description - an example ID was copied
    # verbatim by qwen3 in live testing ("F-C008-1a2b3c4d5e").
    finding_id: str = Field(
        description="Exact finding_id of a confirmed finding, copied from get_rule_findings"
    )
    rank: int = Field(description="1 = most urgent")
    rationale: str = Field(description="Why this matters in an OT/ICS context")


class PotentialConcern(BaseModel):
    """A NEW concern the agent infers that no deterministic rule produced."""

    title: str
    resource_name: str = Field(description="Exact name of the affected container/image/network")
    category: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    explanation: str
    remediation: str
    evidence_refs: list[str] = Field(
        description="Finding IDs, CVE IDs or inspect field paths that support this concern"
    )


class AgentAssessment(BaseModel):
    """Structured output of DockerSecurityAssessmentAgent."""

    executive_summary: str
    overall_risk: Literal["critical", "high", "medium", "low"]
    prioritized_findings: list[PrioritizedItem]
    potential_concerns: list[PotentialConcern]
    recommendations: list[str]
    limitations: list[str]


# ---------------------------------------------------------------------------
# 2. The final report
# ---------------------------------------------------------------------------


class ModelInfo(BaseModel):
    profile: str
    provider: str
    model: str
    settings: dict[str, Any] = Field(default_factory=dict)


class MCPServerInfo(BaseModel):
    name: str
    role: str
    command: str
    version: str = ""
    approved_tools: list[str] = Field(default_factory=list)
    connected: bool = False
    error: str | None = None


class DockerEndpointInfo(BaseModel):
    """Which Docker API endpoint a live run used, and whether it was the read-only proxy."""

    docker_host: str
    require_proxy: bool  # config setting; False = the proxy requirement was disabled
    proxy_verified: bool  # the endpoint refused GET /secrets with 403 (read-only proxy)
    docker_version: str = ""

    @property
    def unenforced_warning(self) -> str | None:
        """Text for the run's security warning, or None when the proxy was enforced."""
        if self.require_proxy:
            return None
        detected = (
            "the read-only proxy was nevertheless detected"
            if self.proxy_verified
            else "the endpoint was NOT verified as the read-only proxy, so the MCP servers "
            "may have had full, unfiltered Docker API access"
        )
        return (
            f"SECURITY: require_proxy is disabled for this run. Docker endpoint "
            f"'{self.docker_host}': {detected}."
        )


class ContainerRow(BaseModel):
    name: str
    image: str
    state: str
    user: str
    privileged: bool
    networks: list[str]
    published_ports: list[str]
    finding_count: int = 0


class ImageRow(BaseModel):
    name: str
    id: str
    digest: str | None
    created: str
    size_mb: float
    used_by: list[str]
    vuln_counts: dict[str, int] = Field(default_factory=dict)
    scan_status: str = "not scanned"


class NetworkRow(BaseModel):
    name: str
    driver: str
    internal: bool
    subnets: list[str]
    containers: list[str]


class ImageVulnerabilitySummary(BaseModel):
    image: str
    image_id: str
    digest: str | None
    scanner_version: str
    counts: dict[str, int]
    top_vulnerabilities: list[dict[str, Any]]  # highest-severity first, capped


class PrioritizedEntry(BaseModel):
    rank: int
    finding_id: str
    title: str
    resource_name: str
    severity: str
    rationale: str
    ranked_by: Literal["agent", "deterministic"]


class RunMetrics(BaseModel):
    started_at: datetime
    finished_at: datetime | None = None
    duration_seconds: float = 0.0
    collection_seconds: float = 0.0
    scan_seconds: float = 0.0
    agent_seconds: float = 0.0
    tool_calls_total: int = 0
    tool_calls_agent: int = 0
    tool_calls_blocked: int = 0
    tool_calls_by_name: dict[str, int] = Field(default_factory=dict)
    redactions: int = 0
    model_requests: int = 0
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None


class ReportSummary(BaseModel):
    overall_risk: str
    risk_source: Literal["agent", "deterministic"]
    executive_summary: str
    containers_total: int
    containers_running: int
    images_total: int
    networks_total: int
    volumes_total: int
    findings_by_severity: dict[str, int]
    vulnerable_images: int
    total_vulnerabilities: dict[str, int]


class Report(BaseModel):
    """Contents of report.json (report.md is rendered from this)."""

    report_version: str = "1.0"
    run_id: str
    status: str
    objective: str
    generated_at: datetime
    model: ModelInfo | None
    prompt_version: str
    mcp_servers: list[MCPServerInfo]
    docker_endpoint: DockerEndpointInfo | None = None  # None in replay mode (no Docker access)
    manifest_sha256: str | None = None  # outputs/<run_id>/manifest.json (see manifest.py)
    config_sha256: str | None = None  # same value = same experimental configuration
    snapshot_id: str
    snapshot_captured_at: datetime
    docker_version: str
    docker_platform: str
    summary: ReportSummary
    containers: list[ContainerRow]
    images: list[ImageRow]
    networks: list[NetworkRow]
    findings: list[Finding]  # confirmed (rule + scanner), sorted
    potential_concerns: list[Finding]  # agent-proposed, validated
    rejected_agent_claims: list[Finding]  # failed validation (kept for transparency)
    vulnerabilities: list[ImageVulnerabilitySummary]
    prioritized: list[PrioritizedEntry]
    recommendations: list[str]
    limitations: list[str]
    errors: list[str]
    metrics: RunMetrics
