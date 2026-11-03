"""Defensive Docker security assessment agent.

High-level map of the package (read in this order to understand the flow):

    config.py               Load YAML config + .env into typed Pydantic settings.
    cli.py                  `docker-audit` command-line interface (Typer).
    pipeline.py             One assessment run, end to end (the "main" workflow).

    mcp/                    Everything between the app and the MCP servers:
        policy.py             which tools / arguments are allowed (allow-list).
        redaction.py          scrub secrets out of tool results.
        shaping.py            shrink big tool results before the LLM sees them.
        recorder.py           log every tool call (for metrics + SQLite).
        servers.py            GuardedMCPServer = MCP client + policy + redaction.
        registry.py           build servers from config, health checks, setup.

    inventory/              Turn raw `docker inspect` JSON into typed assets.
    security/               Deterministic rules, Trivy parsing, scan orchestration,
                            validation of the LLM's output, and the agent-vs-rules
                            comparison.
    llm/                    Model factory (OpenAI / Ollama / vLLM) + capability checks.
    agents/                 The single DockerSecurityAssessmentAgent.
    memory/                 SQLite: agent sessions + structured assessment store.
    reporting/              agent, deterministic and comparison reports (.json + .md).
    schemas/                Pydantic data models shared by all of the above.
"""

__version__ = "0.1.0"

# Bumped whenever the agent's instructions or first message change, so runs
# with different prompts can be told apart when comparing models.
#   v1 - findings listed in the first message; generic "verify" workflow
#   v2 - summary-only first message; explicit evidence-gathering workflow;
#        assessment-infrastructure containers labelled in evidence tools
#   v3 - evidence tools take optional arguments and return real error messages;
#        no example finding ID in the output schema
#   v4 - MCP tools only (no evidence tools, no deterministic findings); the first
#        message is the objective + out-of-scope containers; the agent reports its
#        own findings with tool/field/value evidence
#   v5 - coverage: inspect every container and scan every image on a checklist
#        before finishing; one finding per affected container
#   v6 - (with harness h2) one container at a time, recording each container's
#        section right after analysing it; tool results carry references (E7)
#        and can be fetched back; final findings only for what no section covers
PROMPT_VERSION = "v6"

# Bumped whenever the harness around the agent changes what the model sees or
# can do, independently of the prompt text. Recorded in every run manifest.
#   h1 - full shaped tool results stay in context for the whole run; results cut
#        mid-text at max_tool_result_chars
#   h2 - lossless shaping (inspect -> "Path: value" lines, Trivy grouped by package,
#        exact duplicates removed, cut at line boundaries); every full result stored
#        (tool_outputs) under a reference + evidence_get; per-container sections
#        (record_container_section) merged into the assessment; older results
#        replaced by reference stubs before each model call (keep the last N);
#        exact repeat calls answered with the earlier reference
HARNESS_VERSION = "h2"
