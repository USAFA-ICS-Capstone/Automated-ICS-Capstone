# Agent Security Assessment — `run-20261116-152200-9f39`

**Agent status:** ok · **Overall risk (agent):** CRITICAL · **Generated:** 2026-11-16 15:28 UTC

**Model:** `local-vllm` (vllm / `Qwen/Qwen3-32B`) · **Prompt:** v14 · **Snapshot:** `snap-af65f58660943b35`

> What the agent found by itself with read-only MCP tools. It did not see the deterministic findings. The findings are the agent's own claims and were not checked against the collected data: review them by hand.

## 1. Summary

The Docker environment hosting the ICS lab presents multiple high-risk attack paths to the physical process. The most critical vulnerabilities are the simulation container's unrestricted Docker socket access (E8) and the router container's multi-network bridging with elevated capabilities (E7). These create direct pathways for container escape and network manipulation. The PLC and EWS containers (E2, E3) have CAP_NET_ADMIN and root execution, which could allow protocol-level attacks if compromised. The HMI and kali containers (E4, E6) also have network capabilities that could be exploited via the DMZ network. All containers on the ICS network (plc, EWS, simulation) have no resource limits or hardened security profiles, weakening isolation. The audit agent container (E1) has no direct process network access but could be used for lateral movement if other vectors are exploited.

Findings: 35 (critical 2, high 8, medium 22, low 3)


## 2. Findings

#### 🟠 `F-AGENT-3ee7b3f1f9` — CAP_NET_ADMIN capability added

- **Resource:** unknown `plc`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN]`

**Why it matters:** Allows network configuration changes that could be exploited to manipulate ICS network traffic or bypass segmentation.

#### 🟡 `F-AGENT-4a5bfa7da5` — Root user execution

- **Resource:** unknown `plc`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `""`

**Why it matters:** Running as root increases risk of privilege escalation if container is compromised, potentially allowing access to process network assets.

#### 🟡 `F-AGENT-327973f105` — No resource limits configured

- **Resource:** unknown `plc`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CpuShares` = `0`
  - `HostConfig.Memory` = `0`

**Why it matters:** Unbounded resource access could allow denial-of-service attacks against the PLC or process network if container is compromised.

#### 🟡 `F-AGENT-68b8ed9dde` — No seccomp/AppArmor profile applied

- **Resource:** unknown `plc`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.AppArmorProfile` = `""`
  - `HostConfig.SecurityOpt` = `null`

**Why it matters:** Default security profiles may not restrict ICS-specific attack vectors like protocol manipulation or hardware access.

#### 🟠 `F-AGENT-27dff1d59f` — CAP_NET_ADMIN capability added

- **Resource:** unknown `EWS`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN]`

**Why it matters:** Allows network configuration changes that could be exploited to manipulate ICS network traffic or bypass segmentation.

#### 🟡 `F-AGENT-b9ae22d9f2` — Root user execution

- **Resource:** unknown `EWS`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `"root"`

**Why it matters:** Running as root increases risk of privilege escalation if container is compromised, potentially allowing access to process network assets.

#### 🔵 `F-AGENT-222b782ba6` — Weak default VNC password

- **Resource:** unknown `EWS`
- **Category:** other · **Severity:** low · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.Env` = `VNC_PASSWORD=changeme`

**Why it matters:** Default credentials increase risk of brute-force attacks against the engineering workstation's VNC interface.

#### 🟡 `F-AGENT-4b79045bca` — No resource limits configured

- **Resource:** unknown `EWS`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CpuShares` = `0`
  - `HostConfig.Memory` = `0`

**Why it matters:** Unbounded resource access could allow denial-of-service attacks against the EWS or process network if container is compromised.

#### 🟡 `F-AGENT-102095922f` — No seccomp/AppArmor profile applied

- **Resource:** unknown `EWS`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.AppArmorProfile` = `""`
  - `HostConfig.SecurityOpt` = `null`

**Why it matters:** Default security profiles may not restrict ICS-specific attack vectors like protocol manipulation or hardware access.

#### 🟠 `F-AGENT-1545824c3d` — CAP_NET_ADMIN capability added

- **Resource:** unknown `HMI`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN]`

**Why it matters:** Allows network configuration changes that could be exploited to manipulate DMZ/ICS network traffic or bypass segmentation.

#### 🟡 `F-AGENT-4ba659fa47` — Root user execution

- **Resource:** unknown `HMI`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `""`

**Why it matters:** Running as root increases risk of privilege escalation if container is compromised, potentially allowing access to process network assets.

#### 🔵 `F-AGENT-904ebf7a85` — Default credentials in environment variables

- **Resource:** unknown `HMI`
- **Category:** other · **Severity:** low · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.Env` = `MYSQL_ROOT_PASSWORD=root`

**Why it matters:** Default credentials increase risk of brute-force attacks against the HMI's database and web interface.

#### 🟡 `F-AGENT-3ac0ca075c` — No resource limits configured

- **Resource:** unknown `HMI`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CpuShares` = `0`
  - `HostConfig.Memory` = `0`

**Why it matters:** Unbounded resource access could allow denial-of-service attacks against the HMI or process network if container is compromised.

#### 🟡 `F-AGENT-e67a0c2ec2` — No seccomp/AppArmor profile applied

- **Resource:** unknown `HMI`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.AppArmorProfile` = `""`
  - `HostConfig.SecurityOpt` = `null`

**Why it matters:** Default security profiles may not restrict ICS-specific attack vectors like protocol manipulation or hardware access.

#### 🟡 `F-AGENT-66fc18c8f7` — Root user execution

- **Resource:** unknown `caldera`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `""`

**Why it matters:** Running as root increases risk of privilege escalation if container is compromised, potentially allowing access to process network assets.

#### 🟡 `F-AGENT-91de073e20` — No resource limits configured

- **Resource:** unknown `caldera`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CpuShares` = `0`
  - `HostConfig.Memory` = `0`

**Why it matters:** Unbounded resource access could allow denial-of-service attacks against the Caldera framework or process network if container is compromised.

#### 🟡 `F-AGENT-8468a4092e` — No seccomp/AppArmor profile applied

- **Resource:** unknown `caldera`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.AppArmorProfile` = `""`
  - `HostConfig.SecurityOpt` = `null`

**Why it matters:** Default security profiles may not restrict ICS-specific attack vectors like protocol manipulation or hardware access.

#### 🟠 `F-AGENT-a6ecff23a3` — CAP_NET_ADMIN capability added

- **Resource:** unknown `kali`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN]`

**Why it matters:** Allows network configuration changes that could be exploited to manipulate DMZ/ICS network traffic or bypass segmentation.

#### 🟡 `F-AGENT-416bc7657a` — Root user execution

- **Resource:** unknown `kali`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `"root"`

**Why it matters:** Running as root increases risk of privilege escalation if container is compromised, potentially allowing access to process network assets.

#### 🔵 `F-AGENT-a6a13994ff` — Weak default VNC password

- **Resource:** unknown `kali`
- **Category:** other · **Severity:** low · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.Env` = `VNC_PASSWORD=changeme`

**Why it matters:** Default credentials increase risk of brute-force attacks against the Kali container's VNC interface.

#### 🟡 `F-AGENT-8d6a960c67` — No resource limits configured

- **Resource:** unknown `kali`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CpuShares` = `0`
  - `HostConfig.Memory` = `0`

**Why it matters:** Unbounded resource access could allow denial-of-service attacks against the Kali container or process network if compromised.

#### 🟡 `F-AGENT-b16b7ac2ae` — No seccomp/AppArmor profile applied

- **Resource:** unknown `kali`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.AppArmorProfile` = `""`
  - `HostConfig.SecurityOpt` = `null`

**Why it matters:** Default security profiles may not restrict ICS-specific attack vectors like protocol manipulation or hardware access.

#### 🟠 `F-AGENT-6e48de016e` — CAP_NET_ADMIN and CAP_NET_RAW capabilities added

- **Resource:** unknown `router`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN, CAP_NET_RAW]`

**Why it matters:** Allows full network configuration and raw socket access, creating a direct attack vector between admin, DMZ, and ICS networks.

#### 🟡 `F-AGENT-28cbf5665f` — Root user execution

- **Resource:** unknown `router`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `""`

**Why it matters:** Running as root increases risk of privilege escalation if container is compromised, potentially allowing access to process network assets.

#### 🟡 `F-AGENT-5b3698fb66` — No resource limits configured

- **Resource:** unknown `router`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CpuShares` = `0`
  - `HostConfig.Memory` = `0`

**Why it matters:** Unbounded resource access could allow denial-of-service attacks against the network gateway or process network if container is compromised.

#### 🟡 `F-AGENT-e25dab8638` — No seccomp/AppArmor profile applied

- **Resource:** unknown `router`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.AppArmorProfile` = `""`
  - `HostConfig.SecurityOpt` = `null`

**Why it matters:** Default security profiles may not restrict ICS-specific attack vectors like protocol manipulation or hardware access.

#### 🟠 `F-AGENT-a21d73b782` — CAP_NET_ADMIN capability added

- **Resource:** unknown `simulation`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN]`

**Why it matters:** Allows network configuration changes that could be exploited to manipulate ICS network traffic or bypass segmentation.

#### 🟡 `F-AGENT-f65d1c6949` — Root user execution

- **Resource:** unknown `simulation`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `""`

**Why it matters:** Running as root increases risk of privilege escalation if container is compromised, potentially allowing access to process network assets.

#### 🔴 `F-AGENT-e5f56d678c` — Docker socket mounted with read-write access

- **Resource:** unknown `simulation`
- **Category:** other · **Severity:** critical · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Mounts[0].Mode` = `rw`

**Why it matters:** Provides full control over the Docker host, enabling container escape and arbitrary container creation/deletion.

#### 🟡 `F-AGENT-52bc362d42` — No resource limits configured

- **Resource:** unknown `simulation`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CpuShares` = `0`
  - `HostConfig.Memory` = `0`

**Why it matters:** Unbounded resource access could allow denial-of-service attacks against the simulation or process network if container is compromised.

#### 🟡 `F-AGENT-c5f44ff0c4` — No seccomp/AppArmor profile applied

- **Resource:** unknown `simulation`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.AppArmorProfile` = `""`
  - `HostConfig.SecurityOpt` = `null`

**Why it matters:** Default security profiles may not restrict ICS-specific attack vectors like protocol manipulation or hardware access.

#### 🔴 `F-AGENT-63ad804e59` — Simulation container provides Docker host control via socket mount

- **Resource:** unknown `simulation`
- **Category:** other · **Severity:** critical · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Mounts[0].Mode` = `rw`

**Why it matters:** A compromised simulation container could execute arbitrary Docker commands, bypassing all container isolation and directly accessing the PLC and other process network assets.

#### 🟠 `F-AGENT-45b6a3dd59` — Router container bridges admin, DMZ, and ICS networks with elevated privileges

- **Resource:** unknown `router`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN, CAP_NET_RAW]`

**Why it matters:** CAP_NET_ADMIN and CAP_NET_RAW capabilities on a container connected to all three networks create a direct attack vector between security zones.

#### 🟠 `F-AGENT-9ba584c723` — PLC container has network administration capabilities on process network

- **Resource:** unknown `plc`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN]`

**Why it matters:** Allows potential manipulation of ICS network traffic directly from the PLC container if compromised.

#### 🟡 `F-AGENT-306efcf269` — Multiple containers on process network lack resource limits

- **Resource:** unknown `grficsv3_b-ics-net`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CpuShares` = `0`
  - `HostConfig.Memory` = `0`

**Why it matters:** Unbounded resource access on the process network could allow denial-of-service attacks against critical ICS assets.


## 3. Limitations (stated by the agent)

- No image vulnerability scanning tools were used in this assessment
- Stopped containers were not inspected
- No network traffic analysis tools were used to confirm protocol exposure


## 4. Execution metrics

| Metric | Value |
|---|---|
| Duration (total / collect / scan / agent) | 407.69s / 0.36s / 29.21s / 375.98s |
| Tool calls (total / by agent / blocked) | 480 / 15 / 0 |
| Model requests | 16 |
| Tokens (in / out / total) | 397929 / 11055 / 408984 |


**MCP servers:**

| Server | Role | Version | Connected | Approved tools |
|---|---|---|---|---|
| docker | docker_inspection | docker-mcp-server==2.2.7 | yes | container_list, container_inspect, image_list, image_inspect, image_history, network_list, network_inspect, volume_list, volume_inspect, system_info, system_version |
| trivy | image_scanner | v0.68.2 | yes | scan_image, findings_list, findings_get, trivy_version |


**Tool calls by name:** `docker.container_inspect`×7, `docker.container_list`×2, `docker.image_list`×1, `docker.network_list`×1, `docker.system_version`×1, `docker.volume_list`×1, `harness.record_container_section`×7, `trivy.findings_list`×451, `trivy.scan_image`×8, `trivy.trivy_version`×1
