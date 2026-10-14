"""Result shaping: make tool results small and readable for the LLM.

Real numbers from docker-mcp-server against a 20-container host:
``container_list`` returns the *full* inspect document of every container,
about 158 KB of JSON. Sending that to a local 14B model would blow its context
window, and it is mostly noise (log paths, cgroup details...).

So, **for agent calls only**, results pass through ``shape_result``:

* list tools are compacted to a one-line-per-resource summary, which tells the
  agent what exists so it can call ``*_inspect`` on the interesting ones;
* trivy-mcp results get readable keys (it uses one-letter keys and numeric
  severities) and lose its embedded "instructions for the assistant" ``meta``
  block, which is untrusted text we don't want steering the model;
* anything still too long is truncated with an explicit marker.

The application's own collector (inventory/collector.py) does NOT use shaping:
it needs the complete documents for the deterministic rules.
"""

from __future__ import annotations

import json
from typing import Any

# Trivy's numeric severity scale (from trivy-mcp's finding_schema).
TRIVY_SEVERITY = {0: "UNKNOWN", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
TRIVY_CATEGORY = {0: "vulnerability", 1: "misconfiguration", 2: "license", 3: "secret"}


def _short_id(value: str) -> str:
    return value.removeprefix("sha256:")[:12]


def _container_summary(item: dict[str, Any]) -> dict[str, Any]:
    """Compact one container (works for full inspect docs and sparse list entries)."""
    if "Names" in item:  # sparse /containers/json entry
        name = (item.get("Names") or ["?"])[0].lstrip("/")
        ports = [
            f"{p.get('IP', '')}:{p.get('PublicPort')}->{p.get('PrivatePort')}/{p.get('Type')}"
            for p in item.get("Ports") or []
            if p.get("PublicPort")
        ]
        networks = list(((item.get("NetworkSettings") or {}).get("Networks") or {}).keys())
        return {
            "id": _short_id(item.get("Id", "")),
            "name": name,
            "image": item.get("Image"),
            "state": item.get("State"),
            "published_ports": ports,
            "networks": networks,
        }
    # Full inspect document.
    host_cfg = item.get("HostConfig") or {}
    ports = []
    for cport, bindings in (host_cfg.get("PortBindings") or {}).items():
        for b in bindings or []:
            ports.append(f"{b.get('HostIp') or '0.0.0.0'}:{b.get('HostPort')}->{cport}")
    return {
        "id": _short_id(item.get("Id", "")),
        "name": (item.get("Name") or "").lstrip("/"),
        "image": (item.get("Config") or {}).get("Image"),
        "state": (item.get("State") or {}).get("Status"),
        "published_ports": ports,
        "networks": list(((item.get("NetworkSettings") or {}).get("Networks") or {}).keys()),
    }


def _image_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": _short_id(item.get("Id", "")),
        "tags": item.get("RepoTags") or [],
        "created": item.get("Created"),
        "size_mb": round((item.get("Size") or 0) / 1_000_000, 1),
    }


def _network_summary(item: dict[str, Any]) -> dict[str, Any]:
    subnets = [c.get("Subnet") for c in ((item.get("IPAM") or {}).get("Config") or [])]
    return {
        "name": item.get("Name"),
        "id": _short_id(item.get("Id", "")),
        "driver": item.get("Driver"),
        "internal": item.get("Internal"),
        "subnets": [s for s in subnets if s],
    }


def _volume_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {"name": item.get("Name"), "driver": item.get("Driver")}


def _trivy_scan_summary(item: dict[str, Any]) -> dict[str, Any]:
    """scan_image returns {batch_id, counts: {artifact: {sev_num: n}}, meta: {...}}."""
    counts: dict[str, int] = {}
    for per_artifact in (item.get("counts") or {}).values():
        for sev, n in (per_artifact or {}).items():
            label = TRIVY_SEVERITY.get(int(sev), str(sev))
            counts[label] = counts.get(label, 0) + int(n)
    return {
        "batch_id": item.get("batch_id"),
        "target": (item.get("meta") or {}).get("target"),
        "counts_by_severity": counts,
        "hint": "Call findings_list with this batchID to see individual vulnerabilities.",
    }


def trivy_finding_readable(f: dict[str, Any]) -> dict[str, Any]:
    """Translate trivy-mcp's compact keys into readable ones."""
    return {
        "key": f.get("i"),
        "id": f.get("id"),
        "category": TRIVY_CATEGORY.get(f.get("c"), f.get("c")),
        "severity": TRIVY_SEVERITY.get(f.get("s"), f.get("s")),
        "package": f.get("an"),
        "installed_version": f.get("av"),
        "fixed_version": f.get("fv"),
        "has_fix": f.get("fx"),
        "artifact_type": f.get("at"),
        "title": f.get("title"),
    }


def _trivy_findings_page(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "findings": [trivy_finding_readable(f) for f in item.get("findings") or []],
        "next_token": item.get("next_token") or None,
    }


def shape_result(tool: str, items: list[Any]) -> Any:
    """Return an LLM-friendly version of a tool result (list of parsed JSON items)."""
    dicts = [i for i in items if isinstance(i, dict)]
    if tool == "container_list":
        return [_container_summary(i) for i in dicts]
    if tool == "image_list":
        return [_image_summary(i) for i in dicts]
    if tool == "network_list":
        return [_network_summary(i) for i in dicts]
    if tool == "volume_list":
        return [_volume_summary(i) for i in dicts]
    if tool == "scan_image" and dicts:
        return _trivy_scan_summary(dicts[0])
    if tool == "findings_list" and dicts:
        return _trivy_findings_page(dicts[0])
    if tool == "container_inspect" and dicts:
        # Drop host-path bookkeeping fields that are pure noise for analysis.
        doc = dict(dicts[0])
        for noisy in ("ResolvConfPath", "HostnamePath", "HostsPath", "LogPath", "GraphDriver"):
            doc.pop(noisy, None)
        return doc
    # Single item -> unwrap; otherwise return the list unchanged.
    return items[0] if len(items) == 1 else items


def to_text(value: Any, max_chars: int) -> str:
    """Serialise for the model and enforce the size cap."""
    text = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
    if len(text) <= max_chars:
        return text
    omitted = len(text) - max_chars
    return (
        text[:max_chars]
        + f"\n...[TRUNCATED: {omitted} more characters omitted. Narrow the request, e.g. "
        "inspect a single resource.]"
    )
