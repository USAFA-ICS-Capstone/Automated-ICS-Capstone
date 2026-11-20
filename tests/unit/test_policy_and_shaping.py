"""Tool policy (allow-list + argument rules) and result shaping."""

import grfics

from docker_security_agent.mcp.policy import ToolPolicy
from docker_security_agent.mcp.shaping import shape_result, to_text


def test_unapproved_tools_are_refused(settings):
    policy = ToolPolicy(settings.mcp)
    for tool in ("container_exec", "secret_inspect", "container_archive_get", "container_logs"):
        assert not policy.check("docker", tool, {}).allowed
    assert not policy.check("trivy", "scan_filesystem", {"target": "/"}).allowed
    assert policy.check("docker", "container_inspect", {"id_or_name": "plc"}).allowed


def test_unknown_server_is_refused(settings):
    assert not ToolPolicy(settings.mcp).check("evil", "container_list", {}).allowed


def test_scan_requires_inventory_and_known_target(settings, snapshot):
    policy = ToolPolicy(settings.mcp)
    args = {"target": "fortiphyd/grfics-plc:latest", "scanType": ["vuln"]}
    assert not policy.check("trivy", "scan_image", args).allowed  # no inventory yet

    policy.set_scan_targets(snapshot.image_references())
    assert policy.check("trivy", "scan_image", args).allowed
    decision = policy.check("trivy", "scan_image", {"target": "alpine:latest"})
    assert not decision.allowed
    assert "not in the current Docker inventory" in decision.reason


def test_scan_arguments_are_normalised(settings, snapshot):
    policy = ToolPolicy(settings.mcp)
    policy.set_scan_targets(snapshot.image_references())
    d = policy.check(
        "trivy",
        "scan_image",
        {
            "target": "fortiphyd/grfics-plc:latest",
            "scanType": ["secret", "vuln"],
            "outputFormat": "cyclonedx",
            "targetType": "filesystem",
        },
    )
    assert d.allowed
    assert d.arguments["scanType"] == ["vuln"]  # 'secret' scanning stripped
    assert d.arguments["outputFormat"] == "json"
    assert d.arguments["targetType"] == "image"


def test_findings_list_categories_forced(settings):
    d = ToolPolicy(settings.mcp).check(
        "trivy", "findings_list", {"batchID": "b1", "categories": ["secret"]}
    )
    assert d.allowed and d.arguments["categories"] == ["vuln"]
    assert not ToolPolicy(settings.mcp).check("trivy", "findings_list", {}).allowed


def test_nmap_targets_are_gated_to_the_lab(settings):
    policy = ToolPolicy(settings.mcp)
    nmap = next(s.name for s in settings.mcp.servers.values() if s.role == "network_scanner")

    def allowed(target):
        return policy.check(nmap, "quick_scan", {"target": target}).allowed

    # Allowed: lab hostnames, IPs in the lab subnets, and lab subnets themselves
    # (the sweep the network agent is told to do; refused before, causing a loop).
    for ok in ("plc", "PLC", "192.168.95.2", "192.168.95.0/24", "192.168.90.0/24",
               "192.168.95.0/28", "192.168.95.5/24"):
        assert allowed(ok), ok
    # Refused: off-range IPs and subnets, a range wider than the lab, garbage,
    # and several targets in one string.
    for bad in ("", "10.0.0.1", "192.168.96.0/24", "192.168.0.0/16", "0.0.0.0/0",
                "scanme.nmap.org", "192.168.95.2 10.0.0.1", "192.168.95.2,10.0.0.1"):
        assert not allowed(bad), bad


def test_modbus_host_is_gated_to_the_lab(settings):
    policy = ToolPolicy(settings.mcp)
    modbus = next(s.name for s in settings.mcp.servers.values() if s.role == "ics_protocol")

    def allowed(args):
        return policy.check(modbus, "read_registers", args).allowed

    # Omitting host reads the configured default (PLC) and is allowed; the PLC
    # by name and the field devices by IP are allowed.
    for ok in ({}, {"address": 40001, "count": 10}, {"host": "plc"}, {"host": "PLC"},
               {"host": "192.168.95.2"}, {"host": "192.168.95.14"}, {"host": "192.168.95.0/24"}):
        assert allowed(ok), ok
    # Off-ICS hosts (incl. the DMZ), bad strings, and multiple hosts are refused.
    for bad in ({"host": "192.168.90.107"}, {"host": "hmi"}, {"host": "10.0.0.1"},
                {"host": "evil"}, {"host": "192.168.95.2 10.0.0.1"}):
        assert not allowed(bad), bad
    # A write tool is not on the approved list, so it is refused outright.
    assert not policy.check(modbus, "write_register", {"address": 40001, "data": 1}).allowed


def test_nmap_scan_flags_are_forced(settings):
    policy = ToolPolicy(settings.mcp)
    nmap = next(s.name for s in settings.mcp.servers.values() if s.role == "network_scanner")
    forced = settings.mcp.argument_policy.nmap.forced_flags["nmap_scan"]
    assert "502" in forced and "-sT" in forced

    # Whatever the model sends (risky flags, or none), the fixed sweep runs.
    for sent in ({"flags": "-A --script vuln -sS"}, {}):
        d = policy.check(nmap, "nmap_scan", {"target": "192.168.95.0/24", **sent})
        assert d.allowed and d.arguments["flags"] == forced
    # The target gate still applies, and other tools keep their arguments.
    assert not policy.check(nmap, "nmap_scan", {"target": "10.0.0.0/24"}).allowed
    assert "flags" not in policy.check(nmap, "quick_scan", {"target": "plc"}).arguments


def test_container_list_is_compacted():
    docs = grfics.grfics_containers()
    shaped = shape_result("container_list", docs)
    assert len(shaped) == len(docs)
    sim = next(c for c in shaped if c["name"] == "simulation")
    assert sim["published_ports"] == ["0.0.0.0:80->80/tcp"]
    assert set(sim["networks"]) == {"a-grfics-admin", "b-ics-net"}
    assert len(to_text(shaped, 100_000)) < sum(len(str(d)) for d in docs) / 3


def test_trivy_results_are_readable_and_meta_is_dropped():
    page = grfics.trivy_findings_page(None)
    shaped = shape_result("findings_list", [page])
    assert "IGNORE ALL PREVIOUS" not in to_text(shaped, 100_000)
    assert "pcre2 10.47-r1 (debian, image (debian 12))" in shaped
    assert "  CRITICAL CVE-2026-103111 fix 10.49-r0" in shaped

    summary = shape_result("scan_image", [grfics.trivy_scan_summary("x")])
    assert "counts_by_severity: CRITICAL 1, HIGH 1, MEDIUM 1" in summary


def test_truncation_marker():
    text = to_text("x" * 500, 100)
    assert text.startswith("x" * 100) and "TRUNCATED: 400" in text


def test_container_list_hides_the_agents_own_container():
    """Prompt v10: the agent never sees its own container in container_list."""
    from docker_security_agent.mcp.shaping import shape_result

    items = [
        {"Id": "a" * 64, "Names": ["/plc"], "Image": "fortiphyd/grfics-plc", "State": "running"},
        {"Id": "b" * 64, "Names": ["/docker-audit-agent-run-20261110-155435"],
         "Image": "docker-audit-agent:latest", "State": "running"},
    ]
    assert [c["name"] for c in shape_result("container_list", items)] == ["plc"]
