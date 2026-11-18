# Agent Security Assessment — `run-20261116-164523-819d`

**Agent status:** ok · **Overall risk (agent):** CRITICAL · **Generated:** 2026-11-16 16:51 UTC

**Model:** `local-vllm` (vllm / `Qwen/Qwen3-32B`) · **Prompt:** v14 · **Snapshot:** `snap-eff569f4a9925021`

> What the agent found by itself with read-only MCP tools. It did not see the deterministic findings. The findings are the agent's own claims and were not checked against the collected data: review them by hand.

## 1. Summary

The Docker environment hosting the ICS lab presents critical risks through container escape and network bridging. The simulation container's Docker socket mount (E8) allows unrestricted control over the Docker host, enabling attackers to manipulate any container on the ICS network (192.168.95.45). The router container (E7) operates with CAP_NET_ADMIN and CAP_NET_RAW on both DMZ and ICS networks, creating a direct attack path from external networks to the process network. The PLC container (E2) and EWS workstation (E3) both have CAP_NET_ADMIN on the ICS network, widening the attack surface. These issues combine to create multiple vectors for disrupting physical process integrity and availability. The most dangerous path involves exploiting the simulation container's Docker socket access to reconfigure the router's network rules, then pivoting to the PLC. All ICS assets (PLC, simulation, and engineering workstation) are affected. No containers were skipped due to budget constraints.

Findings: 26 (critical 4, high 11, medium 7, low 4)


## 2. Findings

#### 🟠 `F-AGENT-73459c018e` — CAP_NET_ADMIN capability granted

- **Resource:** unknown `plc`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN]`

**Why it matters:** Allows network configuration changes that could disrupt PLC communication with physical process devices.

#### 🟡 `F-AGENT-4a5bfa7da5` — Root user execution

- **Resource:** unknown `plc`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `""`

**Why it matters:** Running as root increases risk of privilege escalation if container is compromised, potentially affecting process control integrity.

#### 🟡 `F-AGENT-9a945aa20f` — Writable persistent volume mount

- **Resource:** unknown `plc`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Mounts[0].Mode` = `rw`

**Why it matters:** Writable /docker_persistent volume could allow persistence of malicious modifications to PLC configuration files.

#### 🟠 `F-AGENT-b9ae22d9f2` — Root user execution

- **Resource:** unknown `EWS`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `root`

**Why it matters:** Running as root provides full access to container resources, enabling lateral movement to the process network where it resides.

#### 🟠 `F-AGENT-2079ad5927` — CAP_NET_ADMIN capability granted

- **Resource:** unknown `EWS`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN]`

**Why it matters:** Allows network configuration changes on the process network (192.168.95.5), potentially disrupting PLC communications.

#### 🟡 `F-AGENT-4f9852a08f` — Weak VNC password in environment

- **Resource:** unknown `EWS`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.Env` = `VNC_PASSWORD=changeme`

**Why it matters:** Default password for VNC service creates a low-effort entry point to the process network if exposed.

#### 🟠 `F-AGENT-4ba659fa47` — Root user execution

- **Resource:** unknown `HMI`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `""`

**Why it matters:** Running as root provides full container access, enabling lateral movement to the admin network which connects to the ICS network.

#### 🟠 `F-AGENT-be7738c520` — CAP_NET_ADMIN capability granted

- **Resource:** unknown `HMI`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN]`

**Why it matters:** Allows network configuration changes on the DMZ network (192.168.90.107), potentially enabling traffic interception to the ICS network.

#### 🟡 `F-AGENT-a5d5a52ba6` — Weak database credentials in environment

- **Resource:** unknown `HMI`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.Env` = `MYSQL_ROOT_PASSWORD=root`

**Why it matters:** Default MySQL credentials increase risk of database compromise, which could disrupt HMI-PLC communication patterns.

#### 🔵 `F-AGENT-0cf6fdb99a` — External port exposure on DMZ

- **Resource:** unknown `HMI`
- **Category:** other · **Severity:** low · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `NetworkSettings.Ports.8080/tcp[0].HostPort` = `"6081"`

**Why it matters:** Published port 6081/tcp on DMZ network creates an entry point for network-based attacks targeting the HMI interface.

#### 🟡 `F-AGENT-66fc18c8f7` — Root user execution

- **Resource:** unknown `caldera`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `""`

**Why it matters:** Running as root increases risk of privilege escalation if Caldera's exposed port 8888/tcp is compromised via the DMZ network.

#### 🔵 `F-AGENT-4268a920ba` — External port exposure on DMZ

- **Resource:** unknown `caldera`
- **Category:** other · **Severity:** low · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `NetworkSettings.Ports.8888/tcp[0].HostPort` = `"8888"`

**Why it matters:** Published port 8888/tcp on DMZ network (192.168.90.250) creates an entry point for network-based attacks targeting Caldera's attack simulation capabilities.

#### 🟠 `F-AGENT-416bc7657a` — Root user execution

- **Resource:** unknown `kali`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `root`

**Why it matters:** Running as root provides full container access, enabling lateral movement to the admin network which connects to the ICS network.

#### 🟠 `F-AGENT-eba7b9f5c7` — CAP_NET_ADMIN capability granted

- **Resource:** unknown `kali`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN]`

**Why it matters:** Allows network configuration changes on the DMZ network (192.168.90.6), potentially enabling traffic interception to the ICS network.

#### 🟡 `F-AGENT-d1f3968c4b` — Weak VNC password in environment

- **Resource:** unknown `kali`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.Env` = `VNC_PASSWORD=changeme`

**Why it matters:** Default password for VNC service creates a low-effort entry point to the DMZ network if exposed.

#### 🔵 `F-AGENT-04dbf8050d` — External port exposure on DMZ

- **Resource:** unknown `kali`
- **Category:** other · **Severity:** low · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `NetworkSettings.Ports.6080/tcp[0].HostPort` = `"6088"`

**Why it matters:** Published port 6088/tcp on DMZ network (192.168.90.6) creates an entry point for network-based attacks targeting Kali's attack simulation capabilities.

#### 🟠 `F-AGENT-28cbf5665f` — Root user execution

- **Resource:** unknown `router`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `""`

**Why it matters:** Running as root provides full access to container resources, enabling network rule manipulation between DMZ (192.168.90.200) and ICS (192.168.95.200) networks.

#### 🔴 `F-AGENT-1e7ce52d35` — CAP_NET_ADMIN and CAP_NET_RAW capabilities granted

- **Resource:** unknown `router`
- **Category:** other · **Severity:** critical · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN, CAP_NET_RAW]`

**Why it matters:** Allows full network control on the ICS network (192.168.95.200) and raw packet manipulation, directly enabling traffic interception or disruption of PLC communications.

#### 🟡 `F-AGENT-1a7c64f5d7` — Writable network configuration volume

- **Resource:** unknown `router`
- **Category:** other · **Severity:** medium · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Mounts[0].Mode` = `rw`

**Why it matters:** Writable /etc/firewall volume could allow persistence of malicious network rule changes affecting ICS-DMZ traffic routing.

#### 🟠 `F-AGENT-f65d1c6949` — Root user execution

- **Resource:** unknown `simulation`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `""`

**Why it matters:** Running as root provides full container access, enabling lateral movement to the process network (192.168.95.45) where it resides.

#### 🟠 `F-AGENT-8e57f5a67f` — CAP_NET_ADMIN capability granted

- **Resource:** unknown `simulation`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN]`

**Why it matters:** Allows network configuration changes on the ICS network (192.168.95.45), potentially disrupting simulation-PLC communication patterns.

#### 🔴 `F-AGENT-01db367624` — Docker socket bind mount

- **Resource:** unknown `simulation`
- **Category:** other · **Severity:** critical · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Mounts[0].Source` = `/var/run/docker.sock`

**Why it matters:** Mounting the Docker socket (/var/run/docker.sock) grants container escape capabilities to manipulate other containers on the ICS network (192.168.95.45).

#### 🔵 `F-AGENT-42142e2d42` — External port exposure on admin network

- **Resource:** unknown `simulation`
- **Category:** other · **Severity:** low · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `NetworkSettings.Ports.80/tcp[0].HostPort` = `"80"`

**Why it matters:** Published port 80/tcp on admin network (172.18.0.7) creates an entry point for network-based attacks targeting the simulation environment.

#### 🔴 `F-AGENT-915af0a32c` — Docker socket exposure on process network

- **Resource:** unknown `simulation`
- **Category:** other · **Severity:** critical · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Mounts[0].Source` = `/var/run/docker.sock`

**Why it matters:** Mounting the Docker socket in a container on the ICS network (192.168.95.45) allows full control over the Docker host, enabling arbitrary container creation/execution on the process network.

#### 🔴 `F-AGENT-0ac381d160` — ICS network bridging with elevated privileges

- **Resource:** unknown `router`
- **Category:** other · **Severity:** critical · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN, CAP_NET_RAW]`
  - `NetworkSettings.Networks.grficsv3_c-dmz-net.IPAddress` = `192.168.90.200`
  - `NetworkSettings.Networks.grficsv3_b-ics-net.IPAddress` = `192.168.95.200`

**Why it matters:** The router container's position on both DMZ and ICS networks combined with full network manipulation capabilities creates a direct bridge for external attackers to reconfigure process network access.

#### 🟠 `F-AGENT-233d860cea` — Multiple ICS network containers with network capabilities

- **Resource:** unknown `ics_network`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN]`
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN]`
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN]`

**Why it matters:** Three containers on the ICS network (plc, EWS, simulation) all have CAP_NET_ADMIN, creating redundant attack paths for network manipulation and lateral movement.


## 3. Limitations (stated by the agent)

_None._


## 4. Execution metrics

| Metric | Value |
|---|---|
| Duration (total / collect / scan / agent) | 371.51s / 0.29s / 20.68s / 349.52s |
| Tool calls (total / by agent / blocked) | 480 / 15 / 0 |
| Model requests | 16 |
| Tokens (in / out / total) | 388485 / 10291 / 398776 |


**MCP servers:**

| Server | Role | Version | Connected | Approved tools |
|---|---|---|---|---|
| docker | docker_inspection | docker-mcp-server==2.2.7 | yes | container_list, container_inspect, image_list, image_inspect, image_history, network_list, network_inspect, volume_list, volume_inspect, system_info, system_version |
| trivy | image_scanner | v0.68.2 | yes | scan_image, findings_list, findings_get, trivy_version |


**Tool calls by name:** `docker.container_inspect`×7, `docker.container_list`×2, `docker.image_list`×1, `docker.network_list`×1, `docker.system_version`×1, `docker.volume_list`×1, `harness.record_container_section`×7, `trivy.findings_list`×451, `trivy.scan_image`×8, `trivy.trivy_version`×1
