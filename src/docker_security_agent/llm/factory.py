"""Model factory: turn a ``ModelProfile`` into an OpenAI Agents SDK ``Model``.

This is the ONLY place that knows about providers. The agent receives a
``Model`` object and ``ModelSettings`` and has no idea whether it is talking
to OpenAI, Ollama or vLLM - so switching models is purely a config change.

Provider mapping (all are classes shipped with the Agents SDK):

    openai -> OpenAIResponsesModel        (OpenAI's Responses API)
    ollama -> OpenAIChatCompletionsModel  (Ollama's OpenAI-compatible /v1 API)
    vllm   -> OpenAIChatCompletionsModel  (vLLM's OpenAI-compatible server)

Ollama and vLLM both speak the Chat Completions protocol, so the SDK's chat
completions model works with them simply by pointing an ``AsyncOpenAI``
client at a different ``base_url``. No custom LLM orchestration is needed.
"""

from __future__ import annotations

from dataclasses import dataclass

from agents import Model, ModelSettings, OpenAIChatCompletionsModel
from agents.models.openai_responses import OpenAIResponsesModel
from openai import AsyncOpenAI

from docker_security_agent.config import ConfigError, ModelProfile


@dataclass
class ModelBundle:
    """Everything the agent needs to use a model."""

    model: Model
    settings: ModelSettings
    profile: ModelProfile


def _model_settings(profile: ModelProfile) -> ModelSettings:
    kwargs = {}
    if profile.temperature is not None:
        kwargs["temperature"] = profile.temperature
    if profile.max_tokens is not None:
        kwargs["max_tokens"] = profile.max_tokens
    return ModelSettings(**kwargs)


def build_model(profile: ModelProfile) -> ModelBundle:
    """Create the SDK model object for a profile. Raises ConfigError if unusable."""
    if profile.provider == "openai":
        api_key = profile.api_key()
        if not api_key:
            raise ConfigError(
                f"Profile '{profile.name}' needs the {profile.api_key_env} environment variable."
            )
        client = AsyncOpenAI(
            api_key=api_key,
            base_url=profile.base_url or None,  # None -> api.openai.com
            timeout=profile.timeout_seconds,
            max_retries=profile.max_retries,
        )
        model: Model = OpenAIResponsesModel(model=profile.model, openai_client=client)

    elif profile.provider in ("ollama", "vllm"):
        if not profile.base_url:
            raise ConfigError(f"Profile '{profile.name}' needs a base_url.")
        client = AsyncOpenAI(
            base_url=profile.base_url,
            # The OpenAI client insists on *some* key; local servers ignore it
            # unless vLLM was started with --api-key.
            api_key=profile.api_key() or "not-needed",
            timeout=profile.timeout_seconds,
            max_retries=profile.max_retries,
        )
        model = OpenAIChatCompletionsModel(model=profile.model, openai_client=client)

    else:  # pragma: no cover - prevented by the Literal type in config.py
        raise ConfigError(f"Unknown provider '{profile.provider}'")

    return ModelBundle(model=model, settings=_model_settings(profile), profile=profile)
