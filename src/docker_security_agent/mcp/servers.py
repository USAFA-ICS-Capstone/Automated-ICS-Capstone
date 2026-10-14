"""GuardedMCPServer: an MCP client with policy, redaction, shaping and recording.

The OpenAI Agents SDK talks to MCP servers through ``MCPServer`` objects. We
use the SDK's own ``MCPServerStdio`` (it launches the server as a subprocess
and speaks MCP over stdin/stdout) and subclass it to intercept ``call_tool``.

Every tool call goes through the same pipeline::

      caller (LLM via SDK, or our collector)
        |
        v
    [1] ToolPolicy.check        -> refuse unapproved tools / bad arguments
    [2] budget check            -> refuse when the agent is out of tool calls
    [3] MCPServerStdio.call_tool-> the real MCP request (stdio subprocess)
    [4] Redactor.redact_json    -> scrub secrets from the result
    [5] shape_result + to_text  -> (agent only) compact + size-cap the result
    [6] ToolCallRecorder.add    -> metrics + SQLite audit trail
        |
        v
    result returned to the caller

Two entry points:

* ``call_tool(...)``  - what the SDK calls when the *LLM* uses a tool.
                        Returns an MCP ``CallToolResult`` with shaped text.
* ``collect(...)``    - what *our application code* calls (inventory, scans).
                        Returns the full, redacted, parsed JSON items.

Additionally, the SDK's ``tool_output_guardrails`` hook runs
``secret_leak_guardrail`` on everything sent to the model: if a high-confidence
secret pattern somehow survived redaction, the whole result is withheld.

The subprocess environment is minimal: the MCP SDK passes only a few safe
variables (PATH, HOME, ...) plus what we set here, so API keys in our own
environment (e.g. OPENAI_API_KEY) are NOT inherited by MCP servers.
"""

from __future__ import annotations

import json
import time
from typing import Any

from agents import ToolGuardrailFunctionOutput, ToolOutputGuardrailData, tool_output_guardrail
from agents.mcp import MCPServerStdio, create_static_tool_filter
from mcp.types import CallToolResult, TextContent

from docker_security_agent.config import MCPServerConfig
from docker_security_agent.mcp.policy import ToolPolicy
from docker_security_agent.mcp.recorder import ToolCallRecorder
from docker_security_agent.mcp.redaction import Redactor, find_secret_leaks
from docker_security_agent.mcp.shaping import shape_result, to_text


class ToolCallFailed(Exception):
    """Raised by ``collect`` when a tool call is refused or fails."""


@tool_output_guardrail
def secret_leak_guardrail(data: ToolOutputGuardrailData) -> ToolGuardrailFunctionOutput:
    """Last line of defence: withhold any tool output that still looks secret."""
    leaks = find_secret_leaks(str(data.output))
    if leaks:
        return ToolGuardrailFunctionOutput.reject_content(
            "Tool output withheld by the redaction guardrail: it appeared to contain a "
            "credential after sanitisation. Continue the assessment without it.",
            output_info={"patterns": leaks},
        )
    return ToolGuardrailFunctionOutput.allow()


def _parse_content(result: CallToolResult) -> list[Any]:
    """Turn MCP text content blocks into Python objects.

    docker-mcp-server returns one text block per resource (each a JSON doc);
    trivy-mcp returns one JSON text block. Non-JSON text is kept as a string.
    """
    items: list[Any] = []
    for block in result.content:
        text = getattr(block, "text", None)
        if text is None:
            continue  # images/resources are not expected from these servers
        try:
            items.append(json.loads(text))
        except json.JSONDecodeError:
            items.append(text)
    return items


class GuardedMCPServer(MCPServerStdio):
    """``MCPServerStdio`` + policy + redaction + shaping + recording."""

    def __init__(
        self,
        config: MCPServerConfig,
        *,
        docker_host: str,
        policy: ToolPolicy,
        redactor: Redactor,
        recorder: ToolCallRecorder,
        max_result_chars: int,
    ):
        # The Docker endpoint (the read-only proxy) is injected here, so no
        # MCP server ever receives the raw Docker socket path.
        env = {**config.env, "DOCKER_HOST": docker_host}
        super().__init__(
            params={"command": config.command, "args": config.args, "env": env},
            name=config.name,
            # The approved tool list never changes during a run.
            cache_tools_list=True,
            client_session_timeout_seconds=config.client_session_timeout_seconds,
            # [visibility filter] the LLM only ever sees approved tools.
            tool_filter=create_static_tool_filter(allowed_tool_names=config.allowed_tools),
            tool_output_guardrails=[secret_leak_guardrail],
        )
        self.config = config
        self.policy = policy
        self.redactor = redactor
        self.recorder = recorder
        self.max_result_chars = max_result_chars

    # ------------------------------------------------------------------ SDK path

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
        meta: dict[str, Any] | None = None,
    ) -> CallToolResult:
        """Invoked by the Agents SDK when the LLM calls one of our tools."""
        ok, payload = await self._guarded_call(tool_name, arguments, phase="agent", meta=meta)
        if ok:
            text = to_text(shape_result(tool_name, payload), self.max_result_chars)
        else:
            text = str(payload)  # an error/refusal message for the model
        return CallToolResult(content=[TextContent(type="text", text=text)], is_error=not ok)

    # ------------------------------------------------------------ application path

    async def collect(self, tool_name: str, arguments: dict[str, Any] | None = None) -> list[Any]:
        """Call a tool for the application itself; return full redacted JSON items.

        Raises ``ToolCallFailed`` on refusal or error so callers can record it.
        """
        ok, payload = await self._guarded_call(tool_name, arguments, phase="collector")
        if not ok:
            raise ToolCallFailed(str(payload))
        return payload

    # ------------------------------------------------------------- shared pipeline

    async def _guarded_call(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
        *,
        phase: str,
        meta: dict[str, Any] | None = None,
    ) -> tuple[bool, Any]:
        """Run steps [1]-[6] (see module docstring). Returns (ok, items_or_message)."""
        # Arguments are recorded in redacted form only.
        logged_args, _ = self.redactor.redact_json(arguments or {})

        # [1] policy
        decision = self.policy.check(self.name, tool_name, arguments)
        if not decision.allowed:
            self.recorder.add(
                phase=phase,
                server=self.name,
                tool=tool_name,
                arguments=logged_args,
                status="blocked",
                error=decision.reason,
            )
            return False, f"Refused by policy: {decision.reason}"

        # [2] budget (agent calls only)
        if self.recorder.budget_exhausted(phase):
            self.recorder.add(
                phase=phase,
                server=self.name,
                tool=tool_name,
                arguments=logged_args,
                status="budget_exhausted",
            )
            return False, (
                "Tool-call budget exhausted. Do not call more tools; produce your final "
                "assessment now using the evidence you already have."
            )

        # [3] the real MCP call
        started = time.perf_counter()
        try:
            raw = await super().call_tool(tool_name, decision.arguments, meta)
        except Exception as exc:  # transport errors, MCP errors, timeouts
            message, _ = self.redactor.redact_text(f"{type(exc).__name__}: {exc}")
            self.recorder.add(
                phase=phase,
                server=self.name,
                tool=tool_name,
                arguments=logged_args,
                status="error",
                duration_ms=_ms(started),
                error=message,
            )
            return False, f"Tool error: {message}"

        # [4] redaction - always, before anything else touches the data
        items, n_redacted = self.redactor.redact_json(_parse_content(raw))
        size = sum(len(json.dumps(i)) if not isinstance(i, str) else len(i) for i in items)

        if raw.is_error:
            message = " ".join(i if isinstance(i, str) else json.dumps(i) for i in items)[:2000]
            self.recorder.add(
                phase=phase,
                server=self.name,
                tool=tool_name,
                arguments=logged_args,
                status="error",
                duration_ms=_ms(started),
                result_chars=size,
                redactions=n_redacted,
                error=message,
            )
            return False, f"Tool error: {message}"

        # [6] record success ([5] shaping happens in call_tool for the agent path)
        self.recorder.add(
            phase=phase,
            server=self.name,
            tool=tool_name,
            arguments=logged_args,
            status="ok",
            duration_ms=_ms(started),
            result_chars=size,
            redactions=n_redacted,
        )
        return True, items


def _ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)
