"""Model discovery and capability checks.

The agent needs two things from a model:

1. **Tool calling** - otherwise it cannot use the MCP tools at all.
2. **Structured output** - to return an ``AgentAssessment`` JSON object.
   (With ``structured_output: prompted`` we only need the model to follow
   instructions and emit JSON, which most models can do.)

Checks per provider
-------------------
* **Ollama** - ``GET /api/tags`` lists installed models; ``POST /api/show``
  returns a ``capabilities`` array (e.g. ``["completion", "tools",
  "thinking"]``). If ``tools`` is missing, Ollama itself will reject tool
  requests, so we refuse the model up front with a clear message. (On this
  machine, ``dolphin3:latest`` reports only ``completion``.)
* **vLLM** - ``GET /v1/models`` lists served models. vLLM cannot tell us
  whether tool calling was enabled (``--enable-auto-tool-choice``), so
  ``--probe`` sends a tiny real tool-call request to find out.
* **OpenAI** - checks that the API key is set; ``--probe`` confirms the model
  ID is accessible.

``--probe`` checks cost a few tokens of real inference, so they are opt-in.

Context window (Ollama)
-----------------------
Through its OpenAI-compatible ``/v1`` API, Ollama runs a model with the
``num_ctx`` stored in the model's parameters - **4096 tokens by default** -
and ignores per-request overrides (verified on Ollama 0.40.1). The agent's
instructions + tool schemas + evidence need far more than that; Ollama would
silently drop the start of the prompt. ``check_profile`` therefore warns when
``num_ctx`` is below ``profile.min_context_tokens``, and
``create_ollama_context_variant`` creates a variant (e.g.
``qwen3:14b-ctx32k``) with a larger ``num_ctx`` baked in. A variant shares the
original weights; nothing is downloaded.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx
from openai import AsyncOpenAI

from docker_security_agent.config import ModelProfile


@dataclass
class OllamaModel:
    name: str
    size_gb: float
    family: str = ""
    parameter_size: str = ""
    quantization: str = ""
    capabilities: list[str] = field(default_factory=list)
    num_ctx: int | None = None  # None = not set -> Ollama default (4096)

    @property
    def supports_tools(self) -> bool:
        return "tools" in self.capabilities


@dataclass
class CapabilityReport:
    profile: str
    provider: str
    model: str
    reachable: bool = False
    model_available: bool = False
    supports_tools: bool | None = None  # None = unknown (not probed)
    supports_structured_output: bool | None = None
    details: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)  # usable, but likely to misbehave
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Usable for the agent loop (unknown tool support is allowed, False is not)."""
        return (
            self.reachable
            and self.model_available
            and self.supports_tools is not False
            and not self.errors
        )


def ollama_native_base(base_url: str) -> str:
    """http://localhost:11434/v1 -> http://localhost:11434 (Ollama's native API)."""
    return base_url.rstrip("/").removesuffix("/v1")


async def list_ollama_models(
    base_url: str, *, timeout: float = 10, client: httpx.AsyncClient | None = None
) -> list[OllamaModel]:
    """Discover installed Ollama models, including their capabilities."""
    native = ollama_native_base(base_url)
    own_client = client is None
    client = client or httpx.AsyncClient(timeout=timeout)
    try:
        tags = (await client.get(f"{native}/api/tags")).raise_for_status().json()
        models = []
        for m in tags.get("models", []):
            details = m.get("details") or {}
            info = await ollama_model_info(native, m["name"], client=client)
            models.append(
                OllamaModel(
                    name=m["name"],
                    size_gb=round((m.get("size") or 0) / 1e9, 1),
                    family=details.get("family", ""),
                    parameter_size=details.get("parameter_size", ""),
                    quantization=details.get("quantization_level", ""),
                    capabilities=list(info.get("capabilities") or []),
                    num_ctx=parse_num_ctx(info),
                )
            )
        return models
    finally:
        if own_client:
            await client.aclose()


async def ollama_model_info(
    base_url: str, model: str, *, client: httpx.AsyncClient
) -> dict[str, Any]:
    """``POST /api/show`` for one model (returns {} if it fails)."""
    resp = await client.post(f"{ollama_native_base(base_url)}/api/show", json={"model": model})
    return resp.json() if resp.status_code == 200 else {}


OLLAMA_DEFAULT_CONTEXT = 4096


def parse_num_ctx(show: dict[str, Any]) -> int | None:
    """Extract ``num_ctx`` from /api/show's ``parameters`` text block, if set."""
    for line in str(show.get("parameters") or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "num_ctx" and parts[1].isdigit():
            return int(parts[1])
    return None


async def create_ollama_context_variant(
    base_url: str, model: str, num_ctx: int, *, name: str | None = None, timeout: float = 120
) -> str:
    """Create ``<model>-ctx<N>k`` with ``num_ctx`` set; return the new model name.

    Uses Ollama's ``POST /api/create`` with ``from`` + ``parameters`` (the API
    equivalent of a Modelfile ``FROM model`` / ``PARAMETER num_ctx N``).
    Remove it later with ``ollama rm <name>``.
    """
    new_name = name or f"{model}-ctx{num_ctx // 1024}k"
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            f"{ollama_native_base(base_url)}/api/create",
            json={
                "model": new_name,
                "from": model,
                "parameters": {"num_ctx": num_ctx},
                "stream": False,
            },
        )
        resp.raise_for_status()
        status = resp.json().get("status")
        if status != "success":
            raise RuntimeError(f"Ollama create returned status {status!r}")
    return new_name


def _same_model(requested: str, installed: str) -> bool:
    """Ollama treats 'qwen3' and 'qwen3:latest' as the same model."""
    norm = lambda n: n if ":" in n else f"{n}:latest"  # noqa: E731
    return norm(requested) == norm(installed)


# ---------------------------------------------------------------------------
# Probes (real inference requests against an OpenAI-compatible endpoint)
# ---------------------------------------------------------------------------

_PROBE_TOOL = {
    "type": "function",
    "function": {
        "name": "report_status",
        "description": "Report a status string.",
        "parameters": {
            "type": "object",
            "properties": {"status": {"type": "string"}},
            "required": ["status"],
        },
    },
}


async def probe_tool_calling(client: AsyncOpenAI, model: str) -> tuple[bool, str]:
    """Ask the model to call a trivial tool; True if it emits a tool call."""
    try:
        resp = await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "Call report_status with status 'ok'."}],
            tools=[_PROBE_TOOL],
            max_tokens=256,
        )
    except Exception as exc:  # provider-specific errors
        return False, f"tool-call probe failed: {exc}"
    calls = resp.choices[0].message.tool_calls or []
    if calls and calls[0].function.name == "report_status":
        return True, "tool-call probe succeeded"
    return False, "model answered without calling the tool"


async def probe_structured_output(client: AsyncOpenAI, model: str) -> tuple[bool, str]:
    """Ask for a JSON-schema-constrained answer; True if valid JSON comes back."""
    schema = {
        "type": "object",
        "properties": {"risk": {"type": "string", "enum": ["low", "high"]}},
        "required": ["risk"],
        "additionalProperties": False,
    }
    try:
        resp = await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "Answer with risk 'low'."}],
            response_format={
                "type": "json_schema",
                "json_schema": {"name": "probe", "schema": schema, "strict": True},
            },
            max_tokens=256,
        )
        data = json.loads(resp.choices[0].message.content or "")
        return data.get("risk") in ("low", "high"), "structured-output probe succeeded"
    except Exception as exc:
        return False, f"structured-output probe failed: {exc}"


# ---------------------------------------------------------------------------
# Per-profile check
# ---------------------------------------------------------------------------


async def check_profile(
    profile: ModelProfile,
    *,
    probe: bool = False,
    http_client: httpx.AsyncClient | None = None,
) -> CapabilityReport:
    """Run the provider-appropriate checks for one model profile."""
    report = CapabilityReport(profile.name, profile.provider, profile.model)
    own_client = http_client is None
    http = http_client or httpx.AsyncClient(timeout=15)
    try:
        if profile.provider == "ollama":
            await _check_ollama(profile, report, http)
        elif profile.provider == "vllm":
            await _check_vllm(profile, report, http)
        else:
            await _check_openai(profile, report, http, probe)

        if probe and report.reachable and report.model_available and profile.provider != "openai":
            client = AsyncOpenAI(
                base_url=profile.base_url,
                api_key=profile.api_key() or "not-needed",
                timeout=profile.timeout_seconds,
            )
            ok, msg = await probe_tool_calling(client, profile.model)
            report.supports_tools = ok
            report.details.append(msg)
            ok, msg = await probe_structured_output(client, profile.model)
            report.supports_structured_output = ok
            report.details.append(msg)
    except httpx.HTTPError as exc:
        report.errors.append(f"HTTP error talking to {profile.provider}: {exc}")
    finally:
        if own_client:
            await http.aclose()

    if report.supports_tools is False and not any("tool" in e for e in report.errors):
        report.errors.append(
            f"Model '{profile.model}' does not support tool calling, which the agent requires."
        )
    return report


async def _check_ollama(p: ModelProfile, report: CapabilityReport, http: httpx.AsyncClient) -> None:
    if not p.base_url:
        report.errors.append("base_url is required for Ollama profiles")
        return
    native = ollama_native_base(p.base_url)
    try:
        tags = (await http.get(f"{native}/api/tags")).raise_for_status().json()
    except httpx.HTTPError as exc:
        report.errors.append(f"Ollama not reachable at {native}: {exc}. Is `ollama serve` running?")
        return
    report.reachable = True
    installed = [m["name"] for m in tags.get("models", [])]
    match = next((m for m in installed if _same_model(p.model, m)), None)
    if not match:
        report.errors.append(
            f"Model '{p.model}' is not installed in Ollama. "
            f"Installed: {', '.join(installed) or 'none'}."
            f" Install it with: ollama pull {p.model}"
        )
        return
    report.model_available = True
    info = await ollama_model_info(native, match, client=http)
    caps = list(info.get("capabilities") or [])
    report.details.append(f"Ollama capabilities: {caps or 'unknown'}")
    if caps:
        report.supports_tools = "tools" in caps
        if not report.supports_tools:
            report.errors.append(
                f"Model '{p.model}' does not support tool calling (Ollama capabilities: {caps}). "
                "Pick a tool-capable model, e.g. one listed by "
                "`docker-audit models --provider ollama` "
                "with tools=yes."
            )
    # Ollama enforces JSON schemas via its `format` support for completion models.
    report.supports_structured_output = "completion" in caps if caps else None

    num_ctx = parse_num_ctx(info)
    effective = num_ctx or OLLAMA_DEFAULT_CONTEXT
    report.details.append(
        f"context window via /v1: {effective} tokens"
        + ("" if num_ctx else " (Ollama default; num_ctx not set)")
    )
    if effective < p.min_context_tokens:
        report.warnings.append(
            f"Context window {effective} < {p.min_context_tokens} tokens: Ollama will silently "
            "truncate the agent's prompt. Create a larger-context variant with: docker-audit "
            f"models --provider ollama --create-variant {match} --num-ctx 32768 (and use it in "
            "config/models.yaml), or set OLLAMA_CONTEXT_LENGTH on the Ollama server."
        )


async def _check_vllm(p: ModelProfile, report: CapabilityReport, http: httpx.AsyncClient) -> None:
    if not p.base_url:
        report.errors.append("base_url is required for vLLM profiles")
        return
    headers = {"Authorization": f"Bearer {p.api_key()}"} if p.api_key() else {}
    try:
        resp = await http.get(f"{p.base_url.rstrip('/')}/models", headers=headers)
    except httpx.HTTPError as exc:
        report.errors.append(f"vLLM endpoint not reachable at {p.base_url}: {exc}")
        return
    if resp.status_code == 401:
        report.reachable = True
        report.errors.append(f"vLLM rejected the API key (set {p.api_key_env}).")
        return
    if resp.status_code != 200:
        report.errors.append(f"vLLM /models returned HTTP {resp.status_code}")
        return
    report.reachable = True
    served = [m.get("id") for m in resp.json().get("data", [])]
    if p.model not in served:
        report.errors.append(f"Model '{p.model}' is not served. Served: {', '.join(served)}")
        return
    report.model_available = True
    report.details.append(
        "Tool calling is unknown until probed (vLLM needs --enable-auto-tool-choice and "
        "--tool-call-parser). Run with --probe to test."
    )


async def _check_openai(
    p: ModelProfile, report: CapabilityReport, http: httpx.AsyncClient, probe: bool
) -> None:
    if not p.api_key():
        report.errors.append(f"Environment variable {p.api_key_env} is not set.")
        return
    report.reachable = True
    report.supports_tools = True  # all current OpenAI chat models support tools
    report.supports_structured_output = True
    if not probe:
        report.model_available = True
        report.details.append("API key present (model availability not probed)")
        return
    base = (p.base_url or "https://api.openai.com/v1").rstrip("/")
    resp = await http.get(
        f"{base}/models/{p.model}", headers={"Authorization": f"Bearer {p.api_key()}"}
    )
    if resp.status_code == 200:
        report.model_available = True
        report.details.append("model is accessible with this API key")
    else:
        report.errors.append(f"OpenAI returned HTTP {resp.status_code} for model '{p.model}'")
