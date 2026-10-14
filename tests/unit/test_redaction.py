"""Sensitive-information redaction."""

import pytest

from docker_security_agent.config import load_settings
from docker_security_agent.mcp.redaction import REDACTED, Redactor, find_secret_leaks


@pytest.fixture
def redactor() -> Redactor:
    return Redactor(load_settings().mcp.redaction)


def test_env_values_redacted_names_kept(redactor):
    env, n = redactor.redact_env(
        [
            "PATH=/usr/bin",
            "MYSQL_ROOT_PASSWORD=Sup3rS3cret!",
            "NODE_VERSION=18.20.8",
            "APP_MODE=debug",
        ]
    )
    assert env == [
        "PATH=/usr/bin",  # allow-listed
        f"MYSQL_ROOT_PASSWORD={REDACTED}",
        "NODE_VERSION=18.20.8",  # *_VERSION allow-listed
        f"APP_MODE={REDACTED}",  # not allow-listed -> value removed (over-redaction)
    ]
    assert n == 2


def test_inspect_document_env_and_keys(redactor):
    doc = {
        "Config": {
            "Env": ["FWUI_SECRET_KEY=some-long-secret-you-generate", "LANG=C.UTF-8"],
            "Labels": {"db.password": "hunter2", "maintainer": "ops"},
        },
        "AuthConfig": {"Password": "pw123", "Username": "bob"},
    }
    out, n = redactor.redact_json(doc)
    assert out["Config"]["Env"][0] == f"FWUI_SECRET_KEY={REDACTED}"
    assert out["Config"]["Env"][1] == "LANG=C.UTF-8"
    assert out["Config"]["Labels"]["db.password"] == REDACTED
    assert out["Config"]["Labels"]["maintainer"] == "ops"
    assert out["AuthConfig"]["Password"] == REDACTED
    assert n == 3
    # The input must not be modified.
    assert doc["Config"]["Labels"]["db.password"] == "hunter2"


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("postgres://admin:hunter2@db:5432/ics", "hunter2"),
        ("token ghp_abcdefghijklmnopqrstuvwxyz0123456789 here", "ghp_abcdefghijklmnopqrstuvwxyz"),
        ("key AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP"),
        ("Authorization: Bearer abcdefghijklmnop1234567890", "abcdefghijklmnop1234567890"),
        ("run --db-password Pa55word now", "Pa55word"),
        ("start.sh API_KEY=abc123xyz", "abc123xyz"),
        ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.c2lnbmF0dXJlLXZhbHVl", "eyJhbGciOi"),
        (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
            "MIIEow",
        ),
    ],
)
def test_secret_shaped_strings(redactor, text, secret):
    cleaned, n = redactor.redact_text(text)
    assert secret not in cleaned
    assert n >= 1


def test_harmless_values_untouched(redactor):
    doc = {
        "Id": "sha256:" + "a" * 64,
        "Image": "fortiphyd/grfics-plc:latest",
        "next_token": "eyJhZnRlcl9pZCI6IjRmYTQwNTc0In0",  # trivy pagination cursor
        "Cmd": ["python", "simulator.py", "--port", "502"],
        "HostConfig": {"NetworkMode": "b-ics-net"},
    }
    out, n = redactor.redact_json(doc)
    assert out == doc
    assert n == 0


def test_leak_detector(redactor):
    assert find_secret_leaks("ghp_abcdefghijklmnopqrstuvwxyz0123456789")
    assert not find_secret_leaks(f"GITHUB_TOKEN={REDACTED}")
    cleaned, _ = redactor.redact_text("my key is sk-abcdefghijklmnopqrstuvwxyz123")
    assert not find_secret_leaks(cleaned)
