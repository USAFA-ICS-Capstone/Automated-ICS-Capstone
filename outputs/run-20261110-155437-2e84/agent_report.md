# Agent Security Assessment — `run-20261110-155437-2e84`

**Agent status:** ok · **Overall risk (agent):** CRITICAL · **Generated:** 2026-11-10 15:59 UTC

**Model:** `local-vllm` (vllm / `Qwen/Qwen3-32B`) · **Prompt:** v9 · **Snapshot:** `snap-18000523abbceada`

> What the agent found by itself with read-only MCP tools. It did not see the deterministic findings. The findings are the agent's own claims and were not checked against the collected data: review them by hand.

## 1. Summary

The Docker environment hosts multiple ICS-related images but lacks running containers beyond the audit agent. Critical risks include non-internal bridge networks exposing ICS services to the host network and potential vulnerabilities in unscanned images. High-risk issues like missing resource limits and privilege escalation capabilities cannot be verified due to tool constraints.

Findings: 2 (critical 1, high 1)


## 2. Findings

#### 🔴 `F-AGENT-622b15efd5` — Non-Internal Bridge Networks

- **Resource:** unknown `grficsv3_b-ics-net, grficsv3_c-dmz-net`
- **Category:** other · **Severity:** critical · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Internal` = `false`
  - `Driver` = `bridge`

**Why it matters:** Non-internal bridge networks allow containers to access the host's network stack, increasing attack surface. In OT environments, this could enable lateral movement between ICS and DMZ networks.

#### 🟠 `F-AGENT-47ff110f5e` — Unscanned ICS Images

- **Resource:** unknown `ics_range-attacker:latest, ics_range-process-simulator:latest`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Tags` = `ics_range-attacker:latest`
  - `Tags` = `ics_range-process-simulator:latest`

**Why it matters:** Critical ICS components cannot be assessed for vulnerabilities due to policy restrictions. Unpatched software in these images could allow exploitation of known ICS protocol weaknesses.


## 3. Limitations (stated by the agent)

- Failed to scan ics_range-attacker:latest and ics_range-process-simulator:latest due to policy restrictions
- No running containers to assess runtime configurations
- Unable to verify container resource limits and capability restrictions


## 4. Execution metrics

| Metric | Value |
|---|---|
| Duration (total / collect / scan / agent) | 290.92s / 0.83s / 36.32s / 251.83s |
| Tool calls (total / by agent / blocked) | 476 / 14 / 2 |
| Model requests | 6 |
| Tokens (in / out / total) | 72858 / 7841 / 80699 |


**MCP servers:**

| Server | Role | Version | Connected | Approved tools |
|---|---|---|---|---|
| docker | docker_inspection | docker-mcp-server==2.2.7 | yes | container_list, container_inspect, image_list, image_inspect, image_history, network_list, network_inspect, volume_list, volume_inspect, system_info, system_version |
| trivy | image_scanner | v0.68.2 | yes | scan_image, findings_list, findings_get, trivy_version |


**Tool calls by name:** `docker.container_list`×3, `docker.image_list`×2, `docker.network_inspect`×2, `docker.network_list`×2, `docker.system_version`×1, `docker.volume_list`×1, `trivy.findings_list`×451, `trivy.scan_image`×13, `trivy.trivy_version`×1
