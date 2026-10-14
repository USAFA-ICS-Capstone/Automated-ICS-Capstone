"""Helpers that turn fixture documents into application objects."""

from __future__ import annotations

from datetime import UTC, datetime

import grfics

from docker_security_agent.config import Settings
from docker_security_agent.inventory.collector import finalize_snapshot
from docker_security_agent.inventory.parsers import (
    parse_container,
    parse_image,
    parse_network,
    parse_volume,
)
from docker_security_agent.mcp.redaction import Redactor
from docker_security_agent.schemas.assets import InventorySnapshot


def build_snapshot(settings: Settings) -> InventorySnapshot:
    """Parse the fixture documents exactly like the collector does (incl. redaction)."""
    redactor = Redactor(settings.mcp.redaction)
    red = lambda docs: redactor.redact_json(docs)[0]  # noqa: E731
    snap = InventorySnapshot(
        captured_at=datetime(2026, 10, 8, 12, 0, tzinfo=UTC),
        docker_version="29.7.2",
        docker_platform="Docker Desktop (test fixture)",
        containers=[parse_container(d) for d in red(grfics.grfics_containers())],
        images=[parse_image(d) for d in red(grfics.grfics_images())],
        networks=[parse_network(d) for d in red(grfics.grfics_networks())],
        volumes=[parse_volume(d) for d in red(grfics.grfics_volumes())],
    )
    return finalize_snapshot(snap)
