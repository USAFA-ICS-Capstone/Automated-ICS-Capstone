"""Sensitive-data redaction.

Docker metadata routinely contains secrets: database passwords in
environment variables, tokens in command lines, credentials embedded in
URLs. None of those values may reach

  * the LLM provider (which may be a third-party API),
  * application logs, or
  * the SQLite assessment store.

``Redactor`` is applied to *every* MCP tool result inside
``GuardedMCPServer`` (see servers.py) before the result is used for anything.
It works in three layers:

1. **Environment lists** (``Env: ["NAME=value", ...]``): the NAME is kept
   (it is useful evidence, e.g. ``DB_PASSWORD`` exists) but the VALUE is
   replaced with ``<redacted>`` unless the name is on an allow-list of
   clearly harmless variables such as ``PATH``.
2. **Sensitive keys**: any JSON key that looks like ``*password*``,
   ``*token*``... has its scalar value replaced.
3. **Secret-shaped strings**: regexes catch private keys, cloud/API tokens,
   JWTs, bearer tokens, ``user:password@host`` URLs and ``--password x`` style
   command-line arguments wherever they appear.

The design errs towards over-redaction: losing a harmless value is cheap,
leaking a credential is not. Rules only ever need to know that a secret
*exists*, never what it is.
"""

from __future__ import annotations

import copy
import fnmatch
import re
from typing import Any

from docker_security_agent.config import RedactionConfig

REDACTED = "<redacted>"

# --- Layer 3 patterns. Each is (compiled regex, replacement).
# Replacements keep a little context (e.g. the URL scheme/user) so evidence
# stays readable while the secret part disappears.
_TEXT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # PEM private keys (multi-line blocks).
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "<redacted-private-key>",
    ),
    # scheme://user:password@host  ->  scheme://user:<redacted>@host
    (re.compile(r"(\b[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+):([^/\s@]+)@"), r"\1:" + REDACTED + "@"),
    # AWS access key IDs.
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    # GitHub tokens.
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), REDACTED),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"), REDACTED),
    # OpenAI / Anthropic style secret keys.
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), REDACTED),
    # Slack tokens.
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"), REDACTED),
    # JSON Web Tokens (three base64url segments, first starts with eyJ).
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), REDACTED),
    # Authorization: Bearer <token>
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}"), r"\1 " + REDACTED),
    # NAME=value / NAME: value where NAME looks secret (inside free text,
    # e.g. a container command "app --db DB_PASSWORD=hunter2").
    (
        re.compile(
            r"(?i)\b([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)"
            r"[A-Za-z0-9_.-]*)(\s*[=:]\s*)(?!<redacted)([^\s,;\"']+)"
        ),
        r"\1\2" + REDACTED,
    ),
    # --password value / -p value style flags.
    (
        re.compile(
            r"(?i)(--?[A-Za-z0-9-]*(?:password|passwd|secret|token|api-?key)[A-Za-z0-9-]*)"
            r"(\s+)(?!<redacted)(?!-)(\S+)"
        ),
        r"\1\2" + REDACTED,
    ),
]

# High-confidence secret shapes used by the *leak guardrail* (servers.py) as a
# last line of defence. Kept narrower than _TEXT_PATTERNS to avoid false alarms.
LEAK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
]


def find_secret_leaks(text: str) -> list[str]:
    """Return the names of high-confidence secret patterns present in ``text``."""
    return [p.pattern for p in LEAK_PATTERNS if p.search(text)]


def _glob_match(name: str, patterns: list[str]) -> bool:
    """Case-insensitive glob match of ``name`` against any of ``patterns``."""
    lowered = name.lower()
    return any(fnmatch.fnmatchcase(lowered, p.lower()) for p in patterns)


class Redactor:
    """Scrubs secrets from strings and nested JSON. Counts what it removed."""

    def __init__(self, config: RedactionConfig):
        self.env_allowlist = config.env_value_allowlist
        self.sensitive_keys = config.sensitive_key_patterns
        self.key_exceptions = {k.lower() for k in config.sensitive_key_exceptions}

    # ---- public API -------------------------------------------------------

    def redact_text(self, text: str) -> tuple[str, int]:
        """Apply the secret-shaped string patterns. Returns (text, n_redactions)."""
        total = 0
        for pattern, replacement in _TEXT_PATTERNS:
            text, n = pattern.subn(replacement, text)
            total += n
        return text, total

    def redact_env(self, entries: list[Any]) -> tuple[list[Any], int]:
        """Redact a Docker ``Env`` list of "NAME=value" strings.

        Keeps NAME, replaces value with <redacted> unless NAME is allow-listed
        AND the value itself does not look like a secret.
        """
        out: list[Any] = []
        count = 0
        for entry in entries:
            if not isinstance(entry, str) or "=" not in entry:
                out.append(entry)
                continue
            name, value = entry.split("=", 1)
            if value and not _glob_match(name, self.env_allowlist):
                out.append(f"{name}={REDACTED}")
                count += 1
            else:
                # Allow-listed: still scrub anything secret-shaped inside it.
                cleaned, n = self.redact_text(value)
                out.append(f"{name}={cleaned}")
                count += n
        return out, count

    def redact_json(self, data: Any) -> tuple[Any, int]:
        """Return a redacted deep copy of ``data`` and the number of redactions."""
        counter = [0]  # list so the nested function can mutate it
        result = self._walk(copy.deepcopy(data), counter)
        return result, counter[0]

    # ---- recursive walker -------------------------------------------------

    def _walk(self, node: Any, counter: list[int]) -> Any:
        if isinstance(node, dict):
            for key in list(node):
                value = node[key]
                if key == "Env" and isinstance(value, list):
                    # Docker's environment list ("NAME=value" strings).
                    node[key], n = self.redact_env(value)
                    counter[0] += n
                elif (
                    str(key).lower() not in self.key_exceptions
                    and _glob_match(str(key), self.sensitive_keys)
                    and _is_scalar_secret(value)
                ):
                    # e.g. {"Password": "..."} or a label "db.password": "..."
                    node[key] = REDACTED
                    counter[0] += 1
                else:
                    node[key] = self._walk(value, counter)
            return node
        if isinstance(node, list):
            return [self._walk(item, counter) for item in node]
        if isinstance(node, str):
            cleaned, n = self.redact_text(node)
            counter[0] += n
            return cleaned
        return node  # numbers, booleans, None


def _is_scalar_secret(value: Any) -> bool:
    """Only redact real values: skip empty strings, booleans, None and containers."""
    if isinstance(value, bool) or value is None:
        return False
    if isinstance(value, str):
        return bool(value) and value != REDACTED
    return isinstance(value, int | float)
