"""Deterministic security rules against the GRFICS-like fixture inventory."""

import pytest

from docker_security_agent.schemas.findings import FindingSource, FindingStatus, Severity
from docker_security_agent.security import rules


@pytest.fixture
def findings(snapshot, settings):
    return rules.evaluate(snapshot, settings.rules)


def _hits(findings, rule_id, resource=None):
    return [
        f
        for f in findings
        if f.rule_id == rule_id and (resource is None or f.resource_name == resource)
    ]


def test_docker_socket_mount_is_critical(findings):
    hit = _hits(findings, "C008")
    assert [f.resource_name for f in hit] == ["simulation"]
    assert hit[0].severity == Severity.CRITICAL
    assert "/var/run/docker.sock" in hit[0].evidence[0].value
    # Most severe finding sorts first.
    assert findings[0].severity == Severity.CRITICAL


def test_dangerous_capabilities(findings):
    router = _hits(findings, "C002", "router")[0]
    assert "NET_ADMIN" in router.title and "NET_RAW" in router.title
    assert router.severity == Severity.MEDIUM  # both configured as medium
    assert {e.value for e in router.evidence} == {"NET_ADMIN", "NET_RAW"}
    # GRFICS adds NET_ADMIN to (almost) every service.
    assert {f.resource_name for f in _hits(findings, "C002")} >= {
        "simulation",
        "plc",
        "EWS",
        "HMI",
        "kali",
        "router",
    }


def test_privileged_and_host_namespace_and_profiles(findings):
    assert _hits(findings, "C001", "bad-debug")[0].severity == Severity.CRITICAL
    pid = _hits(findings, "C004", "bad-debug")
    assert len(pid) == 1 and "PID" in pid[0].title
    prof = _hits(findings, "C005", "bad-debug")[0]
    assert {e.value for e in prof.evidence} == {"seccomp=unconfined", "apparmor=unconfined"}
    # Stopped containers are still analysed but labelled.
    assert "currently exited" in _hits(findings, "C001", "bad-debug")[0].title


def test_sensitive_mounts(findings):
    mounts = _hits(findings, "C009", "bad-debug")
    titles = " ".join(f.title for f in mounts)
    assert "/etc" in titles  # system path (read-only -> medium)
    assert "/Users/alice/.ssh" in titles  # credentials dir (rw -> high)
    assert "projects/grfics/data" not in titles  # ordinary data dir is NOT flagged
    sev = {f.title.split(": ")[1].split(" ")[0]: f.severity for f in mounts}
    assert sev["/etc"] == Severity.MEDIUM
    assert sev["/Users/alice/.ssh"] == Severity.HIGH


def test_root_user(findings):
    root = {f.resource_name for f in _hits(findings, "C003")}
    assert {"simulation", "router", "plc"} <= root
    assert "hardened" not in root


def test_network_rules(findings):
    # router bridges 3 networks; IP forwarding enabled
    assert _hits(findings, "N002", "router")
    assert _hits(findings, "N003", "router")[0].evidence[0].value == "1"
    # published ports are an exposure observation (low), never a vulnerability
    n001 = _hits(findings, "N001", "plc")[0]
    assert n001.severity == Severity.LOW and "not a vulnerability" in n001.explanation
    # hardened binds to 127.0.0.1 -> not flagged
    assert not _hits(findings, "N001", "hardened")
    # internal network not flagged; user-defined non-internal networks are info
    n005 = {f.resource_name for f in _hits(findings, "N005")}
    assert "isolated" not in n005 and "b-ics-net" in n005
    assert {"bridge", "host", "none"}.isdisjoint(n005)


def test_secret_env_names_only(findings):
    s001 = _hits(findings, "S001", "router")[0]
    assert "FWUI_SECRET_KEY" in s001.title
    assert "some-long-secret" not in s001.model_dump_json()
    assert _hits(findings, "S001", "HMI")  # MYSQL_ROOT_PASSWORD


def test_hardened_container_has_no_findings(findings):
    assert not [f for f in findings if f.resource_name == "hardened"]
    assert not [f for f in findings if f.resource_name == "example/hardened:1.2.3"]


def test_image_tag_rule(findings):
    assert _hits(findings, "I001", "fortiphyd/grfics-plc:latest")


def test_all_rule_findings_are_confirmed_with_evidence(findings):
    for f in findings:
        assert f.status == FindingStatus.CONFIRMED
        assert f.source == FindingSource.RULE
        assert f.evidence, f.id
        assert f.remediation and f.explanation


def test_ids_are_deterministic(snapshot, settings):
    a = [f.id for f in rules.evaluate(snapshot, settings.rules)]
    b = [f.id for f in rules.evaluate(snapshot, settings.rules)]
    assert a == b and len(set(a)) == len(a)


def test_config_disable_override_and_ignore(snapshot, settings):
    settings.rules.disabled_rules = ["C007"]
    settings.rules.severity_overrides = {"C003": "high"}
    settings.rules.ignore_containers = ["simulation"]
    found = rules.evaluate(snapshot, settings.rules)
    assert not _hits(found, "C007")
    assert all(f.severity == Severity.HIGH for f in _hits(found, "C003"))
    assert not [f for f in found if f.resource_name == "simulation"]


def test_exclude_stopped(snapshot, settings):
    settings.rules.include_stopped_containers = False
    found = rules.evaluate(snapshot, settings.rules)
    assert not [f for f in found if f.resource_name == "bad-debug"]
