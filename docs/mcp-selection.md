# MCP Server Selection and Evaluation (Milestone 1, Phase 1)

Research date: 2026-10-08. Every claim below was checked against the project's source,
package metadata, or official documentation on that date. Items that could not be verified
are marked **unverified**.

## Evaluation criteria

1. Supported inspection tools
2. Maintenance and documentation
3. Docker Desktop compatibility
4. OpenAI Agents SDK compatibility
5. MCP transport
6. Ability to restrict tools
7. Ability to prevent Docker modifications
8. Handling of sensitive metadata
9. Ease of installation

---

## 1. Docker inspection candidates

### 1a. docker-mcp-server (L337-org): **SELECTED**

- Repo: https://github.com/L337-org/docker-mcp · PyPI: `docker-mcp-server`
- Version reviewed: **2.2.7** (PyPI upload 2026-10-07). Releases are frequent: 2.2.5
  on 08-18, 2.2.6 on 09-10, 2.2.7 on 10-07. MIT. It has a test suite and architecture docs.
- Install: `uvx docker-mcp-server==2.2.7`. Transport: **stdio**.
- Daemon endpoint: any `DOCKER_HOST` (`unix://`, `tcp://`, `ssh://`), so it works with
  Docker Desktop and with a socket proxy.
- Tool safety model: `TOOL_CATEGORIES` in `docker_mcp/server.py` assigns each tool
  `READ_ONLY`, `MUTATING`, or `DESTRUCTIVE`. `DOCKER_MCP_SERVER_READONLY=1` registers
  **only** `READ_ONLY` tools, so the others never appear in `list_tools`.
- READ_ONLY tools in 2.2.7 (from source):
  `system_ping, system_version, system_info, system_df, system_events, container_inspect,
  container_list, container_logs, container_stats, container_top, container_diff,
  container_wait, container_archive_get, image_inspect, image_registry_data, image_list,
  image_search, image_history, network_inspect, network_list, volume_inspect, volume_list`
  (plus non-engine read tools such as host listing).
- Concerns:
  - "Read-only" still includes `container_archive_get`, which reads files out of
    containers, and `container_logs`, which can contain secrets. Our allow-list excludes
    both.
  - There is no built-in redaction of environment-variable values in `container_inspect`
    output, so we must redact.
  - Small community footprint (few stars). Oddity: on 2026-10-08 the default branch of
    the GitHub repo contained only a README, while the tags and PyPI sdist contain the full
    source. **We pin the PyPI version** and review the sdist.
- Verdict: the best fit. It has the broadest inspection coverage, and its read-only mode
  works by unregistering tools, not by refusing them at runtime.

### 1b. mcp-server-docker (ckreiling): **REJECTED**

- Repo: https://github.com/ckreiling/mcp-server-docker · PyPI `mcp-server-docker` 0.3.0
  (2026-08-07)
- Tools: `list_containers, create_container, run_container, recreate_container,
  start_container, fetch_container_logs, stop_container, remove_container, list_images,
  pull_image, push_image, build_image, remove_image, list_networks, create_network,
  remove_network, list_volumes, create_volume, remove_volume`
- It has no read-only mode, and most tools mutate. There is no `container_inspect`
  equivalent with full HostConfig. It only lists. It also offers a "docker_compose"
  plan/apply prompt.
- Verdict: rejected. It exposes excessive privileges and lacks inspection depth.

### 1c. Other community servers (not selected)

| Server | Notes | Reason not selected |
|---|---|---|
| `williajm/mcp_docker` | Docs describe a read-only mode via `SAFETY_ALLOW_MODERATE_OPERATIONS=false` | GitHub repo returned "not found" on 2026-10-08, so we can't review or pin from source |
| `mbround18/dockerops-mcp` | Includes `exec`, `compose`, and `run` with a read-only flag | Its surface centers on operations (exec/compose); not suited to a defensive audit |
| `dockroot-mcp`, `jhot21/docker-mcp` | Small read-only servers | No image or network inspection tools; low maturity |
| `ArkTechNWA/docker-mcp` | Permission tiers | Marked "planning" |

### 1d. Docker MCP Toolkit / MCP Gateway: **not used in Milestone 1**

- Docs: https://docs.docker.com/ai/mcp-catalog-and-toolkit/
- Provides a catalog of containerized MCP servers, profiles, and a gateway that clients
  connect to. It is useful for *discovering and running* MCP servers, and possibly for
  hosting trivy-mcp later.
- It does **not** by itself provide Docker container-inventory tools. Per-server tool
  allow-listing in the gateway is not described on the overview page (**unverified**).
  Parts of the gateway governance offering are invite-only.
- Verdict: it adds an extra layer without a capability we need. Our YAML registry and SDK
  tool filters already control which servers and tools are enabled. We can revisit it if
  containerized MCP servers become a requirement.

---

## 2. Vulnerability scanning

### trivy-mcp (Aqua Security): **SELECTED**

- Repo: https://github.com/aquasecurity/trivy-mcp (MIT, official Aqua project). Last
  commit reviewed: `076c9b4`, 2025-12-17.
- Install: `brew install trivy && trivy plugin install mcp`. Run: `trivy mcp`
  (default transport `stdio`; `streamable-http` and `sse` are also available, bound to
  `localhost` by default). Option `--trivy-binary` selects a specific Trivy binary.
- Tools (from `pkg/tools`):
  - `scan_image(target, scanType[], severities[], outputFormat, fixedOnly, targetType)`
  - `scan_filesystem(...)`, `scan_repository(...)`: **not approved**. They reach the
    host filesystem and remote repositories respectively.
  - `findings_list(batchID, minSeverity, categories[], limit, token)`: paginated findings
    from a scan batch
  - `findings_get(batchID, id)`: single finding detail
  - `trivy_version()`
- Scan results are stored in an in-memory batch, and the tool returns a summary plus
  `batchID`. This works well for an agent, because the full CVE list never floods the
  context window at once.
- Aqua Platform integration is optional (`--use-aqua-platform`) and is not used.
- Local images: Trivy reads images from the Docker Engine via `DOCKER_HOST`. Image export
  is a GET request, so it works through the read-only socket proxy with `IMAGES=1`.
- Vulnerability DB: downloaded on first run into Trivy's cache. Offline use requires a
  pre-populated cache (`--skip-db-update` at the Trivy level). Whether trivy-mcp passes
  that flag through is **unverified** and will be tested in Phase 3.
- Concerns: about 10 months since the last commit. Mitigation: pin Trivy and plugin
  versions. Fallback: call `trivy image --format json` directly in a small, documented
  adapter.

---

## 3. Docker API boundary

### tecnativa/docker-socket-proxy: **SELECTED**

- Repo: https://github.com/Tecnativa/docker-socket-proxy (HAProxy-based)
- `POST=0` (the default) allows only GET/HEAD on enabled sections. We enable `CONTAINERS`,
  `IMAGES`, `NETWORKS`, `VOLUMES`, `INFO`, and `VERSION`. `EXEC`, `BUILD`, `SECRETS`,
  `AUTH`, `SWARM`, `SYSTEM`, and the others stay at their default (denied).
- Published on `127.0.0.1:2375` only. It gives defense in depth: even if an MCP server
  exposes or mis-categorizes a mutating tool, the daemon never sees a write request.

---

## 4. OpenAI Agents SDK compatibility

Verified against https://openai.github.io/openai-agents-python/mcp/ :

- `MCPServerStdio(params={"command", "args", "env"}, cache_tools_list=True,
  tool_filter=create_static_tool_filter(allowed_tool_names=[...]))`
- `MCPServerManager(servers, drop_failed_servers=True, ...)` connects all servers and
  exposes `active_servers` / `failed_servers`, so an unavailable server degrades
  gracefully.
- `Agent(mcp_servers=manager.active_servers, mcp_config={"include_server_in_tool_names": True})`
- `tool_output_guardrails` on local MCP servers can **allow or replace the whole output**
  (`ToolGuardrailFunctionOutput.reject_content`) but cannot partially edit it. We therefore
  redact in a thin wrapper around the server's `call_tool`, and use an output guardrail
  as a final "nothing secret-shaped survived" check.
- SDK requires `mcp>=1.19.0,<3`.

## 5. Verification results (Phases 3 and 8, run on 2026-10-08)

These were checked against the live Docker Desktop host, not taken from documentation:

| Check | Result |
|---|---|
| docker-mcp-server 2.2.7 with `DOCKER_MCP_SERVER_READONLY=1` | **77 tools still registered**, including `secret_inspect`, `secret_list`, `swarm_join_tokens`, `swarm_unlock_key`, `container_archive_get`, `container_logs`, `compose_logs`, `hub_*`, `scout_*`. Read-only mode is not the same as "safe for an LLM". The allow-list exposes 11 of them (`docker-audit mcp check`). |
| docker-mcp-server output format | One MCP text block per resource. Each block is the full Docker Engine API JSON (`container_list` = full inspect docs, about 158 KB for 20 containers). This motivated `mcp/shaping.py`. |
| docker-mcp-server through the proxy | Works with `DOCKER_HOST=tcp://127.0.0.1:2375`. The proxy access log shows only `GET`/`HEAD`. A proxy-blocked call (`secret_list`) comes back as a tool error with HTTP 403. |
| Socket proxy enforcement | `POST /containers/hmi/exec` gives 403, `POST /containers/hmi/stop` gives 403, `GET /secrets` gives 403, `GET /containers/json` gives 200. |
| trivy-mcp v0.0.20 tools | `scan_image`, `scan_filesystem`, `scan_repository`, `findings_list`, `findings_get`, `trivy_version`. `findings_list` requires `batchID`, `minSeverity` and `categories`, and paginates with `token`/`next_token`. |
| trivy-mcp result format | `scan_image` returns `{batch_id, counts{artifact:{sev_num:n}}, meta}`. Findings use compact keys (`id`, `an`, `av`, `fv`, `fx`, `s` = 0..4). The `meta` block contains instructions addressed to the assistant, so we strip it before results reach the model. |
| trivy-mcp quirk | Always runs Trivy with `--skip-update`, so the first scan fails with "--skip-db-update cannot be specified on the first run". `docker-audit setup` and `assess` therefore download the DB first (`trivy image --download-db-only`). |
| trivy-mcp `findings_get` | Takes the internal finding key (`i`), not the CVE ID. |
| Trivy reading local images through the proxy | Works: image export is a GET (`IMAGES=1`). 20 local images (incl. locally built ones) were scanned in about 160 s. |
| Kali-based image | Trivy returned 0 findings (OS not supported). The report lists such images as "not assessed" instead of clean. |
| Agents SDK `tool_output_guardrails` | Can only allow the result or replace the whole result (`reject_content`). Hence redaction happens in `GuardedMCPServer.call_tool`, and the guardrail is a final leak check. |
| MCP SDK v2 | `mcp` 2.x is installed (the Agents SDK supports `<3`). Field names are snake_case (`input_schema`, `is_error`), and `FastMCP` is now `mcp.server.mcpserver.MCPServer`. The test fake server uses it. |

## 6. Final recommendation

| Need | Choice |
|---|---|
| Docker inventory and inspection | docker-mcp-server 2.2.7, `DOCKER_MCP_SERVER_READONLY=1`, allow-list of 11 tools |
| Image vulnerabilities | trivy-mcp (Trivy plugin), allow-list of 4 tools, scan targets validated against inventory |
| Daemon boundary | docker-socket-proxy, GET-only, loopback only |
| Server management | Our own YAML registry and SDK tool filters (Docker MCP Toolkit deferred) |
| Custom code | Policy and redaction wrapper only; no custom MCP server |
