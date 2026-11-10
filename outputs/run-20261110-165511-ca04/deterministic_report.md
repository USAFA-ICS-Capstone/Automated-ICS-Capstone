# Deterministic Security Assessment — `run-20261110-165511-ca04`

**Status:** completed_with_errors · **Overall risk:** CRITICAL (highest severity found) · **Generated:** 2026-11-10 17:20 UTC

**Source:** rules + Trivy only, no AI · **Snapshot:** `snap-8658f4a80deb0683` · **Agent model in this run:** `local-vllm` (see agent_report.md)

**Manifest:** `manifest.json` · sha256 `04c892f3e0f2aa034eecf0ec770a58337b4b96aaf8dd76519c778680bde90c46` · config `4e0af0b80ee84bbbb7a1de9dfa3eee327e01291353c74f52c43b7a5838923f1b`

## 1. Assessment summary

Deterministic checks (rules and Trivy) produced 84 findings (8 critical, 0 high, 25 medium, 42 low, 9 info). No AI was involved in this report.

**Objective:** Assess the security posture of the Docker environment hosting a containerized industrial control system (ICS) lab. Identify container misconfigurations, risky network exposure, missing resource limits, and known image vulnerabilities. Prioritise risks by their impact on an OT environment and give concrete, evidence-based remediation for defenders.

| Critical | High | Medium | Low | Info |
|---|---|---|---|---|
| 8 | 0 | 25 | 42 | 9 |


## 2. Docker environment overview

- Docker engine: 29.7.2 (Docker Desktop 4.88.1 (237512))
- Docker API endpoint: `unix:///var/run/docker.sock` (full Docker access)
- Snapshot captured: 2026-11-10 16:55:12 UTC
- Containers: 8 (8 running) · Images: 13 · Networks: 7 · Volumes: 24
- Images with known vulnerabilities: 7 · Total vulnerabilities: CRITICAL 239, HIGH 4150, MEDIUM 12115, LOW 5247, UNKNOWN 330


## 3. Container inventory

| Container | Image | State | User | Privileged | Networks | Published ports | Findings |
|---|---|---|---|---|---|---|---|
| EWS | fortiphyd/grfics-workstation | running | root | no | grficsv3_a-grfics-admin, grficsv3_b-ics-net | 0.0.0.0:6080->6080/tcp | 10 |
| HMI | fortiphyd/grfics-scadalts | running | (default: root) | no | grficsv3_a-grfics-admin, grficsv3_c-dmz-net | 0.0.0.0:6081->8080/tcp | 10 |
| caldera | fortiphyd/grfics-caldera | running | (default: root) | no | grficsv3_a-grfics-admin, grficsv3_c-dmz-net | 0.0.0.0:8888->8888/tcp | 7 |
| docker-audit-agent-run-20261110-165510 | docker-audit-agent:latest | running | 10001:10001 | no | docker-audit-agent_default | - | 0 |
| kali | fortiphyd/grfics-attacker | running | root | no | grficsv3_a-grfics-admin, grficsv3_c-dmz-net | 0.0.0.0:6088->6080/tcp | 10 |
| plc | fortiphyd/grfics-plc | running | (default: root) | no | grficsv3_a-grfics-admin, grficsv3_b-ics-net | 0.0.0.0:8080->8080/tcp | 9 |
| router | fortiphyd/grfics-router | running | (default: root) | no | grficsv3_a-grfics-admin, grficsv3_b-ics-net, grficsv3_c-dmz-net | 0.0.0.0:51820->51820/udp | 10 |
| simulation | fortiphyd/grfics-simulation | running | (default: root) | no | grficsv3_a-grfics-admin, grficsv3_b-ics-net | 0.0.0.0:80->80/tcp | 10 |


## 4. Image inventory

| Image | ID | Digest | Size (MB) | Used by | Scan | Vulnerabilities |
|---|---|---|---|---|---|---|
| fortiphyd/grfics-workstation:latest | 0e9f4e94459b | fortiphyd/grfics-workstation@sha256:0e9f | 1851.2 | EWS | ok | C:36, H:704, M:2175, L:1218, U:8 |
| docker-audit-agent:latest | 28dc05d81bf6 | docker-audit-agent@sha256:28dc05d81bf670 | 258.5 | docker-audit-agent-run-20261110-165510 | ok | C:4, H:144, M:201, L:119, U:4 |
| fortiphyd/grfics-attacker:latest | 6cd239bfad70 | fortiphyd/grfics-attacker@sha256:6cd239b | 1678.3 | kali | ok | - |
| fortiphyd/grfics-plc:latest | 7397c8440578 | fortiphyd/grfics-plc@sha256:7397c8440578 | 356.8 | plc | ok | C:55, H:1544, M:6197, L:2083, U:121 |
| fortiphyd/grfics-scadalts:latest | 83f3f576e769 | fortiphyd/grfics-scadalts@sha256:83f3f57 | 568.2 | HMI | ok | C:47, H:92, M:146, L:55 |
| fortiphyd/grfics-router:latest | 9b9a167e5c78 | fortiphyd/grfics-router@sha256:9b9a167e5 | 74.8 | router | ok | C:5, H:190, M:354, L:247, U:2 |
| fortiphyd/grfics-caldera:latest | a7a3edc9ef16 | fortiphyd/grfics-caldera@sha256:a7a3edc9 | 2603.5 | caldera | ok | C:85, H:1319, M:2796, L:1247, U:187 |
| fortiphyd/grfics-simulation:latest | ed3517811da2 | fortiphyd/grfics-simulation@sha256:ed351 | 603.5 | simulation | ok | C:7, H:157, M:246, L:278, U:8 |


## 5. Network configuration

| Network | Driver | Internal | Subnets | Containers |
|---|---|---|---|---|
| bridge | bridge | no | 172.17.0.0/16 | - |
| docker-audit-agent_default | bridge | no | 172.22.0.0/16 | docker-audit-agent-run-20261110-165510 |
| grficsv3_a-grfics-admin | bridge | no | 172.18.0.0/16 | EWS, HMI, caldera, kali, plc, router, simulation |
| grficsv3_b-ics-net | bridge | no | 192.168.95.0/24 | EWS, plc, router, simulation |
| grficsv3_c-dmz-net | bridge | no | 192.168.90.0/24 | HMI, caldera, kali, router |
| host | host | no | - | - |
| none | null | no | - | - |


## 6. Prioritized findings

Ordered by severity; within a severity, running resources and configuration issues first.

| # | Severity | Finding | Resource |
|---|---|---|---|
| 1 | critical | `F-C008-95290deee3` Docker socket is mounted into the container | simulation |
| 2 | critical | `F-V001-1e6606cb6a` Image has known vulnerabilities (4 CRITICAL, 144 HIGH, 201 MEDIUM, 119 LOW, 4 UNKNOWN) | docker-audit-agent:latest |
| 3 | critical | `F-V001-ec328b84bb` Image has known vulnerabilities (85 CRITICAL, 1319 HIGH, 2796 MEDIUM, 1247 LOW, 187 UNKNOWN) | fortiphyd/grfics-caldera:latest |
| 4 | critical | `F-V001-5c7f29bdf3` Image has known vulnerabilities (55 CRITICAL, 1544 HIGH, 6197 MEDIUM, 2083 LOW, 121 UNKNOWN) | fortiphyd/grfics-plc:latest |
| 5 | critical | `F-V001-c66c18dcb1` Image has known vulnerabilities (5 CRITICAL, 190 HIGH, 354 MEDIUM, 247 LOW, 2 UNKNOWN) | fortiphyd/grfics-router:latest |
| 6 | critical | `F-V001-885cc6c80e` Image has known vulnerabilities (47 CRITICAL, 92 HIGH, 146 MEDIUM, 55 LOW) | fortiphyd/grfics-scadalts:latest |
| 7 | critical | `F-V001-e3f7e95629` Image has known vulnerabilities (7 CRITICAL, 157 HIGH, 246 MEDIUM, 278 LOW, 8 UNKNOWN) | fortiphyd/grfics-simulation:latest |
| 8 | critical | `F-V001-9e8f54fed8` Image has known vulnerabilities (36 CRITICAL, 704 HIGH, 2175 MEDIUM, 1218 LOW, 8 UNKNOWN) | fortiphyd/grfics-workstation:latest |
| 9 | medium | `F-C002-3dd48dd209` Container adds dangerous capabilities: NET_ADMIN | EWS |
| 10 | medium | `F-C003-26c5cb4867` Container runs as root | EWS |
| 11 | medium | `F-C002-e0e103aff7` Container adds dangerous capabilities: NET_ADMIN | HMI |
| 12 | medium | `F-C003-8d64d544ec` Container runs as root | HMI |
| 13 | medium | `F-C003-ac5aa14d7f` Container runs as root | caldera |
| 14 | medium | `F-C002-4109eb5fd8` Container adds dangerous capabilities: NET_ADMIN | kali |
| 15 | medium | `F-C003-aefe756ad5` Container runs as root | kali |


## 7. Security misconfigurations (77)

Confirmed by deterministic rules. Each finding lists the exact Docker field that supports it.

#### 🔴 `F-C008-95290deee3` — Docker socket is mounted into the container

- **Resource:** container `simulation`
- **Category:** filesystem · **Severity:** critical · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Mounts` = `/var/run/docker.sock -> /var/run/docker.sock (rw)` — even a read-only mount of the socket allows full API use

**Why it matters:** The Docker API socket grants full control of the Docker daemon: anyone who controls this container can start a privileged container that mounts the host filesystem, i.e. root on the host and control of every ICS component. Mounting it ':ro' does NOT help - it only makes the socket file read-only, not the API.

**Remediation:** Remove the socket mount. If the service needs Docker metadata (e.g. a version/status page), give it a filtered read-only proxy such as tecnativa/docker-socket-proxy with POST=0 and only the needed API sections.

#### 🟡 `F-C002-3dd48dd209` — Container adds dangerous capabilities: NET_ADMIN

- **Resource:** container `EWS`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapAdd` = `NET_ADMIN` — can reconfigure interfaces, routes and firewall rules

**Why it matters:** Added capabilities widen what a compromised process can do to the host kernel and network. In an OT lab, NET_ADMIN/NET_RAW on hosts attached to the process network allow traffic manipulation between PLCs and HMIs.

**Remediation:** Remove capabilities that are not strictly required. Start from `cap_drop: [ALL]` and add back only what the service needs; if NET_ADMIN is only used at start-up (e.g. to add routes), configure networking outside the container instead.

#### 🟡 `F-C003-26c5cb4867` — Container runs as root

- **Resource:** container `EWS`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `root` — Config.User

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C002-e0e103aff7` — Container adds dangerous capabilities: NET_ADMIN

- **Resource:** container `HMI`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapAdd` = `NET_ADMIN` — can reconfigure interfaces, routes and firewall rules

**Why it matters:** Added capabilities widen what a compromised process can do to the host kernel and network. In an OT lab, NET_ADMIN/NET_RAW on hosts attached to the process network allow traffic manipulation between PLCs and HMIs.

**Remediation:** Remove capabilities that are not strictly required. Start from `cap_drop: [ALL]` and add back only what the service needs; if NET_ADMIN is only used at start-up (e.g. to add routes), configure networking outside the container instead.

#### 🟡 `F-C003-8d64d544ec` — Container runs as root

- **Resource:** container `HMI`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C003-ac5aa14d7f` — Container runs as root

- **Resource:** container `caldera`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C002-4109eb5fd8` — Container adds dangerous capabilities: NET_ADMIN

- **Resource:** container `kali`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapAdd` = `NET_ADMIN` — can reconfigure interfaces, routes and firewall rules

**Why it matters:** Added capabilities widen what a compromised process can do to the host kernel and network. In an OT lab, NET_ADMIN/NET_RAW on hosts attached to the process network allow traffic manipulation between PLCs and HMIs.

**Remediation:** Remove capabilities that are not strictly required. Start from `cap_drop: [ALL]` and add back only what the service needs; if NET_ADMIN is only used at start-up (e.g. to add routes), configure networking outside the container instead.

#### 🟡 `F-C003-aefe756ad5` — Container runs as root

- **Resource:** container `kali`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `root` — Config.User

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C002-2873066382` — Container adds dangerous capabilities: NET_ADMIN

- **Resource:** container `plc`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapAdd` = `NET_ADMIN` — can reconfigure interfaces, routes and firewall rules

**Why it matters:** Added capabilities widen what a compromised process can do to the host kernel and network. In an OT lab, NET_ADMIN/NET_RAW on hosts attached to the process network allow traffic manipulation between PLCs and HMIs.

**Remediation:** Remove capabilities that are not strictly required. Start from `cap_drop: [ALL]` and add back only what the service needs; if NET_ADMIN is only used at start-up (e.g. to add routes), configure networking outside the container instead.

#### 🟡 `F-C003-cc372401fd` — Container runs as root

- **Resource:** container `plc`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C002-cb7a40b6fd` — Container adds dangerous capabilities: NET_ADMIN, NET_RAW

- **Resource:** container `router`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapAdd` = `NET_ADMIN` — can reconfigure interfaces, routes and firewall rules
  - `HostConfig.CapAdd` = `NET_RAW` — can craft raw packets (spoofing, ARP poisoning on the ICS segment)

**Why it matters:** Added capabilities widen what a compromised process can do to the host kernel and network. In an OT lab, NET_ADMIN/NET_RAW on hosts attached to the process network allow traffic manipulation between PLCs and HMIs.

**Remediation:** Remove capabilities that are not strictly required. Start from `cap_drop: [ALL]` and add back only what the service needs; if NET_ADMIN is only used at start-up (e.g. to add routes), configure networking outside the container instead.

#### 🟡 `F-C003-7964fd467b` — Container runs as root

- **Resource:** container `router`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-N003-7aeee64b55` — IP forwarding enabled inside the container

- **Resource:** container `router`
- **Category:** network-segmentation · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Sysctls.net.ipv4.ip_forward` = `1`

**Why it matters:** The container routes packets between its interfaces. Expected for a router/firewall container, but it makes this container a critical segmentation control: its rule set and hardening determine whether zones are actually isolated.

**Remediation:** Confirm this container is the intended router; harden and monitor it, restrict its management interface, and disable forwarding elsewhere.

#### 🟡 `F-C002-a304afaab2` — Container adds dangerous capabilities: NET_ADMIN

- **Resource:** container `simulation`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapAdd` = `NET_ADMIN` — can reconfigure interfaces, routes and firewall rules

**Why it matters:** Added capabilities widen what a compromised process can do to the host kernel and network. In an OT lab, NET_ADMIN/NET_RAW on hosts attached to the process network allow traffic manipulation between PLCs and HMIs.

**Remediation:** Remove capabilities that are not strictly required. Start from `cap_drop: [ALL]` and add back only what the service needs; if NET_ADMIN is only used at start-up (e.g. to add routes), configure networking outside the container instead.

#### 🟡 `F-C003-dec60cf9f2` — Container runs as root

- **Resource:** container `simulation`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-N002-99512e47c4` — Container bridges multiple networks

- **Resource:** container `EWS`
- **Category:** network-segmentation · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `NetworkSettings.Networks.grficsv3_a-grfics-admin` = `172.18.0.2`
  - `NetworkSettings.Networks.grficsv3_b-ics-net` = `192.168.95.5`

**Why it matters:** A container attached to several networks is a potential bridge between segmentation zones (e.g. DMZ <-> process network). If it is compromised, an attacker can pivot across zones that the network design intends to keep apart. Whether this is intended (a router/firewall) needs human review.

**Remediation:** Attach the container only to the networks it must serve. Route inter-zone traffic through a dedicated, hardened firewall container and keep management networks separate from ICS process networks.

#### 🟡 `F-S001-64963806ad` — Credential-like environment variables: VNC_PASSWORD

- **Resource:** container `EWS`
- **Category:** secrets-hygiene · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.Env` = `VNC_PASSWORD` — variable name; value not reported

**Why it matters:** Secrets passed as environment variables are visible to anyone who can inspect the container (docker inspect, /proc/<pid>/environ) and often leak into logs and crash dumps. The name alone indicates a likely credential.

**Remediation:** Use Docker secrets / mounted secret files with restricted permissions, and rotate any credential that was exposed via the environment.

#### 🟡 `F-N002-30cb74a37d` — Container bridges multiple networks

- **Resource:** container `HMI`
- **Category:** network-segmentation · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `NetworkSettings.Networks.grficsv3_a-grfics-admin` = `172.18.0.6`
  - `NetworkSettings.Networks.grficsv3_c-dmz-net` = `192.168.90.107`

**Why it matters:** A container attached to several networks is a potential bridge between segmentation zones (e.g. DMZ <-> process network). If it is compromised, an attacker can pivot across zones that the network design intends to keep apart. Whether this is intended (a router/firewall) needs human review.

**Remediation:** Attach the container only to the networks it must serve. Route inter-zone traffic through a dedicated, hardened firewall container and keep management networks separate from ICS process networks.

#### 🟡 `F-S001-ab9da515ed` — Credential-like environment variables: MYSQL_PASSWORD, MYSQL_ROOT_PASSWORD, TOMCAT_PASSWORD

- **Resource:** container `HMI`
- **Category:** secrets-hygiene · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.Env` = `MYSQL_PASSWORD` — variable name; value not reported
  - `Config.Env` = `MYSQL_ROOT_PASSWORD` — variable name; value not reported
  - `Config.Env` = `TOMCAT_PASSWORD` — variable name; value not reported

**Why it matters:** Secrets passed as environment variables are visible to anyone who can inspect the container (docker inspect, /proc/<pid>/environ) and often leak into logs and crash dumps. The name alone indicates a likely credential.

**Remediation:** Use Docker secrets / mounted secret files with restricted permissions, and rotate any credential that was exposed via the environment.

#### 🟡 `F-N002-62d3bffac2` — Container bridges multiple networks

- **Resource:** container `caldera`
- **Category:** network-segmentation · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `NetworkSettings.Networks.grficsv3_a-grfics-admin` = `172.18.0.5`
  - `NetworkSettings.Networks.grficsv3_c-dmz-net` = `192.168.90.250`

**Why it matters:** A container attached to several networks is a potential bridge between segmentation zones (e.g. DMZ <-> process network). If it is compromised, an attacker can pivot across zones that the network design intends to keep apart. Whether this is intended (a router/firewall) needs human review.

**Remediation:** Attach the container only to the networks it must serve. Route inter-zone traffic through a dedicated, hardened firewall container and keep management networks separate from ICS process networks.

#### 🟡 `F-N002-18abf99a5e` — Container bridges multiple networks

- **Resource:** container `kali`
- **Category:** network-segmentation · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `NetworkSettings.Networks.grficsv3_a-grfics-admin` = `172.18.0.3`
  - `NetworkSettings.Networks.grficsv3_c-dmz-net` = `192.168.90.6`

**Why it matters:** A container attached to several networks is a potential bridge between segmentation zones (e.g. DMZ <-> process network). If it is compromised, an attacker can pivot across zones that the network design intends to keep apart. Whether this is intended (a router/firewall) needs human review.

**Remediation:** Attach the container only to the networks it must serve. Route inter-zone traffic through a dedicated, hardened firewall container and keep management networks separate from ICS process networks.

#### 🟡 `F-S001-708e44ce10` — Credential-like environment variables: VNC_PASSWORD

- **Resource:** container `kali`
- **Category:** secrets-hygiene · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.Env` = `VNC_PASSWORD` — variable name; value not reported

**Why it matters:** Secrets passed as environment variables are visible to anyone who can inspect the container (docker inspect, /proc/<pid>/environ) and often leak into logs and crash dumps. The name alone indicates a likely credential.

**Remediation:** Use Docker secrets / mounted secret files with restricted permissions, and rotate any credential that was exposed via the environment.

#### 🟡 `F-N002-793b31131f` — Container bridges multiple networks

- **Resource:** container `plc`
- **Category:** network-segmentation · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `NetworkSettings.Networks.grficsv3_a-grfics-admin` = `172.18.0.4`
  - `NetworkSettings.Networks.grficsv3_b-ics-net` = `192.168.95.2`

**Why it matters:** A container attached to several networks is a potential bridge between segmentation zones (e.g. DMZ <-> process network). If it is compromised, an attacker can pivot across zones that the network design intends to keep apart. Whether this is intended (a router/firewall) needs human review.

**Remediation:** Attach the container only to the networks it must serve. Route inter-zone traffic through a dedicated, hardened firewall container and keep management networks separate from ICS process networks.

#### 🟡 `F-N002-d3ec46728d` — Container bridges multiple networks

- **Resource:** container `router`
- **Category:** network-segmentation · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `NetworkSettings.Networks.grficsv3_a-grfics-admin` = `172.18.0.8`
  - `NetworkSettings.Networks.grficsv3_b-ics-net` = `192.168.95.200`
  - `NetworkSettings.Networks.grficsv3_c-dmz-net` = `192.168.90.200`

**Why it matters:** A container attached to several networks is a potential bridge between segmentation zones (e.g. DMZ <-> process network). If it is compromised, an attacker can pivot across zones that the network design intends to keep apart. Whether this is intended (a router/firewall) needs human review.

**Remediation:** Attach the container only to the networks it must serve. Route inter-zone traffic through a dedicated, hardened firewall container and keep management networks separate from ICS process networks.

#### 🟡 `F-S001-a3fb5da0c6` — Credential-like environment variables: FWUI_SECRET_KEY

- **Resource:** container `router`
- **Category:** secrets-hygiene · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.Env` = `FWUI_SECRET_KEY` — variable name; value not reported

**Why it matters:** Secrets passed as environment variables are visible to anyone who can inspect the container (docker inspect, /proc/<pid>/environ) and often leak into logs and crash dumps. The name alone indicates a likely credential.

**Remediation:** Use Docker secrets / mounted secret files with restricted permissions, and rotate any credential that was exposed via the environment.

#### 🟡 `F-N002-87845aa9d9` — Container bridges multiple networks

- **Resource:** container `simulation`
- **Category:** network-segmentation · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `NetworkSettings.Networks.grficsv3_a-grfics-admin` = `172.18.0.7`
  - `NetworkSettings.Networks.grficsv3_b-ics-net` = `192.168.95.45`

**Why it matters:** A container attached to several networks is a potential bridge between segmentation zones (e.g. DMZ <-> process network). If it is compromised, an attacker can pivot across zones that the network design intends to keep apart. Whether this is intended (a router/firewall) needs human review.

**Remediation:** Attach the container only to the networks it must serve. Route inter-zone traffic through a dedicated, hardened firewall container and keep management networks separate from ICS process networks.

#### 🔵 `F-C006-65a8185959` — no-new-privileges is not set

- **Resource:** container `EWS`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-8ca24f2585` — Root filesystem is writable

- **Resource:** container `EWS`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-eb6e6424bf` — Ports published on all host interfaces

- **Resource:** container `EWS`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:6080 -> 6080/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-8bfa97f891` — Missing resource limits: memory, cpu, pids

- **Resource:** container `EWS`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-25bed309a7` — no-new-privileges is not set

- **Resource:** container `HMI`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-0d54ba154f` — Root filesystem is writable

- **Resource:** container `HMI`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-43ec6d6df7` — Ports published on all host interfaces

- **Resource:** container `HMI`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:6081 -> 8080/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-940a8086c5` — Missing resource limits: memory, cpu, pids

- **Resource:** container `HMI`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-819d3d311f` — no-new-privileges is not set

- **Resource:** container `caldera`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-7de0f68e37` — Root filesystem is writable

- **Resource:** container `caldera`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-f7f970283f` — Ports published on all host interfaces

- **Resource:** container `caldera`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:8888 -> 8888/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-f0d17ac36f` — Missing resource limits: memory, cpu, pids

- **Resource:** container `caldera`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-I001-8c6d0e8428` — Image uses a floating tag: fortiphyd/grfics-attacker:latest

- **Resource:** image `fortiphyd/grfics-attacker:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `fortiphyd/grfics-attacker:latest`
  - `used_by` = `kali`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-I001-4caef92d21` — Image uses a floating tag: fortiphyd/grfics-caldera:latest

- **Resource:** image `fortiphyd/grfics-caldera:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `fortiphyd/grfics-caldera:latest`
  - `used_by` = `caldera`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-I001-bdb1b41685` — Image uses a floating tag: fortiphyd/grfics-plc:latest

- **Resource:** image `fortiphyd/grfics-plc:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `fortiphyd/grfics-plc:latest`
  - `used_by` = `plc`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-I001-88b5ab583a` — Image uses a floating tag: fortiphyd/grfics-router:latest

- **Resource:** image `fortiphyd/grfics-router:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `fortiphyd/grfics-router:latest`
  - `used_by` = `router`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-I001-bb96196ac9` — Image uses a floating tag: fortiphyd/grfics-scadalts:latest

- **Resource:** image `fortiphyd/grfics-scadalts:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `fortiphyd/grfics-scadalts:latest`
  - `used_by` = `HMI`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-I001-7eb90dfea9` — Image uses a floating tag: fortiphyd/grfics-simulation:latest

- **Resource:** image `fortiphyd/grfics-simulation:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `fortiphyd/grfics-simulation:latest`
  - `used_by` = `simulation`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-I001-21a668129f` — Image uses a floating tag: fortiphyd/grfics-workstation:latest

- **Resource:** image `fortiphyd/grfics-workstation:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `fortiphyd/grfics-workstation:latest`
  - `used_by` = `EWS`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-C006-90b05b20d2` — no-new-privileges is not set

- **Resource:** container `kali`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-1b41808c96` — Root filesystem is writable

- **Resource:** container `kali`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-91a7946860` — Ports published on all host interfaces

- **Resource:** container `kali`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:6088 -> 6080/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-6cc61b551c` — Missing resource limits: memory, cpu, pids

- **Resource:** container `kali`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-900c886b05` — no-new-privileges is not set

- **Resource:** container `plc`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-b8f03ce2e5` — Root filesystem is writable

- **Resource:** container `plc`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-3b3279d2e4` — Ports published on all host interfaces

- **Resource:** container `plc`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:8080 -> 8080/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-7d85127222` — Missing resource limits: memory, cpu, pids

- **Resource:** container `plc`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-ece826085c` — no-new-privileges is not set

- **Resource:** container `router`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-680ed12089` — Root filesystem is writable

- **Resource:** container `router`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-adad1da766` — Ports published on all host interfaces

- **Resource:** container `router`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:51820 -> 51820/udp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-e08dc3ad08` — Missing resource limits: memory, cpu, pids

- **Resource:** container `router`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-4842990feb` — no-new-privileges is not set

- **Resource:** container `simulation`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-07e97cdbff` — Root filesystem is writable

- **Resource:** container `simulation`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-ed33ce900e` — Ports published on all host interfaces

- **Resource:** container `simulation`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:80 -> 80/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-edd434e85d` — Missing resource limits: memory, cpu, pids

- **Resource:** container `simulation`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C010-62cfc8456a` — No capabilities are dropped

- **Resource:** container `EWS`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-a7768131e4` — No capabilities are dropped

- **Resource:** container `HMI`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-cb365aeab6` — No capabilities are dropped

- **Resource:** container `caldera`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-6d77b01e2e` — No capabilities are dropped

- **Resource:** container `kali`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-9eb404d5f3` — No capabilities are dropped

- **Resource:** container `plc`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-834037d326` — No capabilities are dropped

- **Resource:** container `router`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-be01693dc2` — No capabilities are dropped

- **Resource:** container `simulation`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### ⚪ `F-R002-f9c5a60e95` — No restart policy

- **Resource:** container `EWS`
- **Category:** resources · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.RestartPolicy.Name` = `no`

**Why it matters:** The container will not be restarted automatically after a crash or host reboot, which may affect availability of the simulated process.

**Remediation:** Use `restart: unless-stopped` for services that must stay available.

#### ⚪ `F-R002-d53f655293` — No restart policy

- **Resource:** container `HMI`
- **Category:** resources · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.RestartPolicy.Name` = `no`

**Why it matters:** The container will not be restarted automatically after a crash or host reboot, which may affect availability of the simulated process.

**Remediation:** Use `restart: unless-stopped` for services that must stay available.

#### ⚪ `F-N005-39eae3dfcd` — Network 'docker-audit-agent_default' is not internal (has external egress)

- **Resource:** network `docker-audit-agent_default`
- **Category:** network-segmentation · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Internal` = `False`
  - `Driver` = `bridge`
  - `Containers` = `docker-audit-agent-run-20261110-165510`

**Why it matters:** Containers on this network can open outbound connections through the host. ICS process networks normally should not reach the internet.

**Remediation:** For process/control networks set `internal: true` and provide any required external access through an explicit, monitored gateway.

#### ⚪ `F-N005-7e891f7c81` — Network 'grficsv3_a-grfics-admin' is not internal (has external egress)

- **Resource:** network `grficsv3_a-grfics-admin`
- **Category:** network-segmentation · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Internal` = `False`
  - `Driver` = `bridge`
  - `Containers` = `EWS, HMI, caldera, kali, plc, router, simulation`

**Why it matters:** Containers on this network can open outbound connections through the host. ICS process networks normally should not reach the internet.

**Remediation:** For process/control networks set `internal: true` and provide any required external access through an explicit, monitored gateway.

#### ⚪ `F-N005-69cb24de33` — Network 'grficsv3_b-ics-net' is not internal (has external egress)

- **Resource:** network `grficsv3_b-ics-net`
- **Category:** network-segmentation · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Internal` = `False`
  - `Driver` = `bridge`
  - `Containers` = `EWS, plc, router, simulation`

**Why it matters:** Containers on this network can open outbound connections through the host. ICS process networks normally should not reach the internet.

**Remediation:** For process/control networks set `internal: true` and provide any required external access through an explicit, monitored gateway.

#### ⚪ `F-N005-8272be9e04` — Network 'grficsv3_c-dmz-net' is not internal (has external egress)

- **Resource:** network `grficsv3_c-dmz-net`
- **Category:** network-segmentation · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Internal` = `False`
  - `Driver` = `bridge`
  - `Containers` = `HMI, caldera, kali, router`

**Why it matters:** Containers on this network can open outbound connections through the host. ICS process networks normally should not reach the internet.

**Remediation:** For process/control networks set `internal: true` and provide any required external access through an explicit, monitored gateway.

#### ⚪ `F-R002-6c0d08c538` — No restart policy

- **Resource:** container `kali`
- **Category:** resources · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.RestartPolicy.Name` = `no`

**Why it matters:** The container will not be restarted automatically after a crash or host reboot, which may affect availability of the simulated process.

**Remediation:** Use `restart: unless-stopped` for services that must stay available.

#### ⚪ `F-R002-a374bc27e8` — No restart policy

- **Resource:** container `plc`
- **Category:** resources · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.RestartPolicy.Name` = `no`

**Why it matters:** The container will not be restarted automatically after a crash or host reboot, which may affect availability of the simulated process.

**Remediation:** Use `restart: unless-stopped` for services that must stay available.

#### ⚪ `F-R002-a48d24f21e` — No restart policy

- **Resource:** container `simulation`
- **Category:** resources · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.RestartPolicy.Name` = `no`

**Why it matters:** The container will not be restarted automatically after a crash or host reboot, which may affect availability of the simulated process.

**Remediation:** Use `restart: unless-stopped` for services that must stay available.


## 8. Known image vulnerabilities

Reported by Trivy; CVE IDs, severities and versions are copied verbatim from the scanner.

### fortiphyd/grfics-workstation:latest

Digest: `fortiphyd/grfics-workstation@sha256:0e9f4e94459b37f0d790cd3c8f1cade609dd8f14fbfc1fa07105c1d9df62b5b4` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 36, HIGH 704, MEDIUM 2175, LOW 1218, UNKNOWN 8

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2023-49569 | CRITICAL | github.com/go-git/go-git/v5 | v5.4.2 | 5.11.0 |
| CVE-2023-49569 | CRITICAL | github.com/go-git/go-git/v5 | v5.4.2 | 5.11.0 |
| CVE-2023-49569 | CRITICAL | github.com/go-git/go-git/v5 | v5.4.2 | 5.11.0 |
| CVE-2023-49569 | CRITICAL | github.com/go-git/go-git/v5 | v5.4.2 | 5.11.0 |
| CVE-2024-24790 | CRITICAL | stdlib | v1.21.6 | 1.21.11, 1.22.4 |
| CVE-2024-24790 | CRITICAL | stdlib | v1.21.6 | 1.21.11, 1.22.4 |
| CVE-2024-24790 | CRITICAL | stdlib | v1.21.6 | 1.21.11, 1.22.4 |
| CVE-2024-24790 | CRITICAL | stdlib | v1.21.6 | 1.21.11, 1.22.4 |
| CVE-2025-21613 | CRITICAL | github.com/go-git/go-git/v5 | v5.4.2 | 5.13.0 |
| CVE-2025-21613 | CRITICAL | github.com/go-git/go-git/v5 | v5.4.2 | 5.13.0 |

### docker-audit-agent:latest

Digest: `docker-audit-agent@sha256:28dc05d81bf670b8bf2b38fa3f79916f1f784fdb32acd1aa18547faa50ee88ba` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 4, HIGH 144, MEDIUM 201, LOW 119, UNKNOWN 4

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2025-68121 | CRITICAL | stdlib | v1.25.5 | 1.24.13, 1.25.7, 1.26.0-rc.3 |
| CVE-2026-33186 | CRITICAL | google.golang.org/grpc | v1.76.0 | 1.79.3 |
| CVE-2023-45853 | CRITICAL | zlib1g | 1:1.2.13.dfsg-1 | - |
| CVE-2025-7458 | CRITICAL | libsqlite3-0 | 3.40.1-2+deb12u2 | - |
| CVE-2025-15558 | HIGH | github.com/docker/cli | v29.0.3+incompatible | 29.2.0 |
| CVE-2025-47273 | HIGH | setuptools | 70.3.0 | 78.1.1 |
| CVE-2025-61726 | HIGH | stdlib | v1.25.5 | 1.24.12, 1.25.6 |
| CVE-2025-66564 | HIGH | github.com/sigstore/timestamp-authority | v1.2.9 | 2.0.3 |
| CVE-2026-24051 | HIGH | go.opentelemetry.io/otel/sdk | v1.38.0 | 1.40.0 |
| CVE-2026-25679 | HIGH | stdlib | v1.25.5 | 1.25.8, 1.26.1 |

### fortiphyd/grfics-attacker:latest

Digest: `fortiphyd/grfics-attacker@sha256:6cd239bfad704904054275db07f486d1531e4e61781a7bff3603af428e9b3d8b` · Scanner: Trivy v0.68.2 · Counts: 

_None._

### fortiphyd/grfics-plc:latest

Digest: `fortiphyd/grfics-plc@sha256:7397c8440578dd8e9ff01133445ed264f1166beb5f00fc72d476d738b9797987` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 55, HIGH 1544, MEDIUM 6197, LOW 2083, UNKNOWN 121

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2021-29921 | CRITICAL | python3.9-dev | 3.9.2-1 | 3.9.2-1+deb11u2 |
| CVE-2021-29921 | CRITICAL | libpython3.9-stdlib | 3.9.2-1 | 3.9.2-1+deb11u2 |
| CVE-2021-29921 | CRITICAL | python3.9-venv | 3.9.2-1 | 3.9.2-1+deb11u2 |
| CVE-2021-29921 | CRITICAL | libpython3.9-dev | 3.9.2-1 | 3.9.2-1+deb11u2 |
| CVE-2021-29921 | CRITICAL | python3.9-minimal | 3.9.2-1 | 3.9.2-1+deb11u2 |
| CVE-2021-29921 | CRITICAL | libpython3.9 | 3.9.2-1 | 3.9.2-1+deb11u2 |
| CVE-2021-29921 | CRITICAL | python3.9 | 3.9.2-1 | 3.9.2-1+deb11u2 |
| CVE-2021-29921 | CRITICAL | libpython3.9-minimal | 3.9.2-1 | 3.9.2-1+deb11u2 |
| CVE-2022-36227 | CRITICAL | libarchive13 | 3.4.3-2+deb11u1 | 3.4.3-2+deb11u2 |
| CVE-2022-37454 | CRITICAL | libpython3.9 | 3.9.2-1 | 3.9.2-1+deb11u4 |

### fortiphyd/grfics-scadalts:latest

Digest: `fortiphyd/grfics-scadalts@sha256:83f3f576e769cb6878ee1188ee8ae79708a1efb5260a4c22022ba0b3171b1bbe` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 47, HIGH 92, MEDIUM 146, LOW 55

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2015-1832 | CRITICAL | org.apache.derby:derby | 10.6.1.0 | 10.12.1.1 |
| CVE-2016-1000027 | CRITICAL | org.springframework:spring-web | 4.3.16.RELEASE | 6.0.0 |
| CVE-2016-1000031 | CRITICAL | commons-fileupload:commons-fileupload | 1.3.2 | 1.3.3 |
| CVE-2017-15095 | CRITICAL | com.fasterxml.jackson.core:jackson-databind | 2.8.2 | 2.8.11, 2.9.4, 2.6.7.3, 2.7.9.2 |
| CVE-2017-17485 | CRITICAL | com.fasterxml.jackson.core:jackson-databind | 2.8.2 | 2.9.4, 2.8.11, 2.7.9.2 |
| CVE-2017-7525 | CRITICAL | com.fasterxml.jackson.core:jackson-databind | 2.8.2 | 2.6.7.1, 2.7.9.1, 2.8.9 |
| CVE-2018-11307 | CRITICAL | com.fasterxml.jackson.core:jackson-databind | 2.8.2 | 2.7.9.4, 2.8.11.2, 2.9.6 |
| CVE-2018-14718 | CRITICAL | com.fasterxml.jackson.core:jackson-databind | 2.8.2 | 2.9.7, 2.8.11.3, 2.7.9.5, 2.6.7.3 |
| CVE-2018-14719 | CRITICAL | com.fasterxml.jackson.core:jackson-databind | 2.8.2 | 2.9.7, 2.8.11.3, 2.7.9.5 |
| CVE-2018-14720 | CRITICAL | com.fasterxml.jackson.core:jackson-databind | 2.8.2 | 2.9.7, 2.8.11.3, 2.7.9.5 |

### fortiphyd/grfics-router:latest

Digest: `fortiphyd/grfics-router@sha256:9b9a167e5c78c933a44af0f47f62f6071294aac435e9f8f472a94d33396a94f3` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 5, HIGH 190, MEDIUM 354, LOW 247, UNKNOWN 2

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2026-13221 | CRITICAL | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 |
| CVE-2026-42496 | CRITICAL | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 |
| CVE-2026-8376 | CRITICAL | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 |
| CVE-2023-45853 | CRITICAL | zlib1g | 1:1.2.13.dfsg-1 | - |
| CVE-2025-7458 | CRITICAL | libsqlite3-0 | 3.40.1-2+deb12u2 | - |
| CVE-2026-42497 | HIGH | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 |
| CVE-2026-48962 | HIGH | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 |
| CVE-2026-57432 | HIGH | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 |
| CVE-2026-57433 | HIGH | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 |
| CVE-2023-2953 | HIGH | libldap-2.5-0 | 2.5.13+dfsg-5 | - |

### fortiphyd/grfics-caldera:latest

Digest: `fortiphyd/grfics-caldera@sha256:a7a3edc9ef1661a3d0fbb8ad4fa40540490bc5d50ace08ba363bc36f07c1d5e1` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 85, HIGH 1319, MEDIUM 2796, LOW 1247, UNKNOWN 187

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2022-23806 | CRITICAL | stdlib | v1.16.3 | 1.16.14, 1.17.7 |
| CVE-2022-23806 | CRITICAL | stdlib | v1.15.9 | 1.16.14, 1.17.7 |
| CVE-2022-23806 | CRITICAL | stdlib | v1.15.9 | 1.16.14, 1.17.7 |
| CVE-2022-23806 | CRITICAL | stdlib | v1.13 | 1.16.14, 1.17.7 |
| CVE-2022-23806 | CRITICAL | stdlib | v1.15.9 | 1.16.14, 1.17.7 |
| CVE-2022-23806 | CRITICAL | stdlib | v1.14.2 | 1.16.14, 1.17.7 |
| CVE-2022-23806 | CRITICAL | stdlib | v1.13.5 | 1.16.14, 1.17.7 |
| CVE-2023-24538 | CRITICAL | stdlib | v1.13 | 1.19.8, 1.20.3 |
| CVE-2023-24538 | CRITICAL | stdlib | v1.18.1 | 1.19.8, 1.20.3 |
| CVE-2023-24538 | CRITICAL | stdlib | v1.15.9 | 1.19.8, 1.20.3 |

### fortiphyd/grfics-simulation:latest

Digest: `fortiphyd/grfics-simulation@sha256:ed3517811da2c4a542bf28b5f19f939ade8aa4d7ab1ac2de63c16087b34dd756` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 7, HIGH 157, MEDIUM 246, LOW 278, UNKNOWN 8

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2026-31789 | CRITICAL | openssl | 3.0.16-1~deb12u1 | 3.0.19-1~deb12u2 |
| CVE-2026-31789 | CRITICAL | libssl3 | 3.0.16-1~deb12u1 | 3.0.19-1~deb12u2 |
| CVE-2026-33845 | CRITICAL | libgnutls30 | 3.7.9-2+deb12u4 | 3.7.9-2+deb12u7 |
| CVE-2026-42010 | CRITICAL | libgnutls30 | 3.7.9-2+deb12u4 | 3.7.9-2+deb12u7 |
| CVE-2023-45853 | CRITICAL | zlib1g | 1:1.2.13.dfsg-1 | - |
| CVE-2025-7458 | CRITICAL | libsqlite3-0 | 3.40.1-2+deb12u1 | - |
| CVE-2026-6653 | CRITICAL | libxml2 | 2.9.14+dfsg-1.3~deb12u6 | - |
| CVE-2024-6345 | HIGH | setuptools | 65.5.1 | 70.0.0 |
| CVE-2025-15467 | HIGH | libssl3 | 3.0.16-1~deb12u1 | 3.0.18-1~deb12u2 |
| CVE-2025-15467 | HIGH | openssl | 3.0.16-1~deb12u1 | 3.0.18-1~deb12u2 |

#### 🔴 `F-V001-1e6606cb6a` — Image has known vulnerabilities (4 CRITICAL, 144 HIGH, 201 MEDIUM, 119 LOW, 4 UNKNOWN)

- **Resource:** image `docker-audit-agent:latest`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `4 CRITICAL, 144 HIGH, 201 MEDIUM, 119 LOW, 4 UNKNOWN` — scanner trivy v0.68.2
  - `gobinary/stdlib` = `CVE-2025-68121 CRITICAL installed=v1.25.5 fixed=1.24.13, 1.25.7, 1.26.0-rc.3`
  - `gobinary/google.golang.org/grpc` = `CVE-2026-33186 CRITICAL installed=v1.76.0 fixed=1.79.3`
  - `debian/zlib1g` = `CVE-2023-45853 CRITICAL installed=1:1.2.13.dfsg-1 fixed=none`
  - `debian/libsqlite3-0` = `CVE-2025-7458 CRITICAL installed=3.40.1-2+deb12u2 fixed=none`
  - `gobinary/github.com/docker/cli` = `CVE-2025-15558 HIGH installed=v29.0.3+incompatible fixed=29.2.0`

**Why it matters:** Trivy matched 472 known vulnerabilities in packages of this image (183 have a fixed version available). Image used by: docker-audit-agent-run-20261110-165510. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2025-68121, https://avd.aquasec.com/nvd/cve-2026-33186, https://avd.aquasec.com/nvd/cve-2023-45853, https://avd.aquasec.com/nvd/cve-2025-7458, https://avd.aquasec.com/nvd/cve-2025-15558

#### 🔴 `F-V001-ec328b84bb` — Image has known vulnerabilities (85 CRITICAL, 1319 HIGH, 2796 MEDIUM, 1247 LOW, 187 UNKNOWN)

- **Resource:** image `fortiphyd/grfics-caldera:latest`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `85 CRITICAL, 1319 HIGH, 2796 MEDIUM, 1247 LOW, 187 UNKNOWN` — scanner trivy v0.68.2
  - `gobinary/stdlib` = `CVE-2022-23806 CRITICAL installed=v1.16.3 fixed=1.16.14, 1.17.7`
  - `gobinary/stdlib` = `CVE-2022-23806 CRITICAL installed=v1.15.9 fixed=1.16.14, 1.17.7`
  - `gobinary/stdlib` = `CVE-2022-23806 CRITICAL installed=v1.15.9 fixed=1.16.14, 1.17.7`
  - `gobinary/stdlib` = `CVE-2022-23806 CRITICAL installed=v1.13 fixed=1.16.14, 1.17.7`
  - `gobinary/stdlib` = `CVE-2022-23806 CRITICAL installed=v1.15.9 fixed=1.16.14, 1.17.7`

**Why it matters:** Trivy matched 5634 known vulnerabilities in packages of this image (2492 have a fixed version available). Image used by: caldera. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2022-23806, https://avd.aquasec.com/nvd/cve-2022-23806, https://avd.aquasec.com/nvd/cve-2022-23806, https://avd.aquasec.com/nvd/cve-2022-23806, https://avd.aquasec.com/nvd/cve-2022-23806

#### 🔴 `F-V001-5c7f29bdf3` — Image has known vulnerabilities (55 CRITICAL, 1544 HIGH, 6197 MEDIUM, 2083 LOW, 121 UNKNOWN)

- **Resource:** image `fortiphyd/grfics-plc:latest`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `55 CRITICAL, 1544 HIGH, 6197 MEDIUM, 2083 LOW, 121 UNKNOWN` — scanner trivy v0.68.2
  - `debian/python3.9-dev` = `CVE-2021-29921 CRITICAL installed=3.9.2-1 fixed=3.9.2-1+deb11u2`
  - `debian/libpython3.9-stdlib` = `CVE-2021-29921 CRITICAL installed=3.9.2-1 fixed=3.9.2-1+deb11u2`
  - `debian/python3.9-venv` = `CVE-2021-29921 CRITICAL installed=3.9.2-1 fixed=3.9.2-1+deb11u2`
  - `debian/libpython3.9-dev` = `CVE-2021-29921 CRITICAL installed=3.9.2-1 fixed=3.9.2-1+deb11u2`
  - `debian/python3.9-minimal` = `CVE-2021-29921 CRITICAL installed=3.9.2-1 fixed=3.9.2-1+deb11u2`

**Why it matters:** Trivy matched 10000 known vulnerabilities in packages of this image (3438 have a fixed version available). Image used by: plc. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2021-29921, https://avd.aquasec.com/nvd/cve-2021-29921, https://avd.aquasec.com/nvd/cve-2021-29921, https://avd.aquasec.com/nvd/cve-2021-29921, https://avd.aquasec.com/nvd/cve-2021-29921

#### 🔴 `F-V001-c66c18dcb1` — Image has known vulnerabilities (5 CRITICAL, 190 HIGH, 354 MEDIUM, 247 LOW, 2 UNKNOWN)

- **Resource:** image `fortiphyd/grfics-router:latest`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `5 CRITICAL, 190 HIGH, 354 MEDIUM, 247 LOW, 2 UNKNOWN` — scanner trivy v0.68.2
  - `debian/perl-base` = `CVE-2026-13221 CRITICAL installed=5.36.0-7+deb12u3 fixed=5.36.0-7+deb12u4`
  - `debian/perl-base` = `CVE-2026-42496 CRITICAL installed=5.36.0-7+deb12u3 fixed=5.36.0-7+deb12u4`
  - `debian/perl-base` = `CVE-2026-8376 CRITICAL installed=5.36.0-7+deb12u3 fixed=5.36.0-7+deb12u4`
  - `debian/zlib1g` = `CVE-2023-45853 CRITICAL installed=1:1.2.13.dfsg-1 fixed=none`
  - `debian/libsqlite3-0` = `CVE-2025-7458 CRITICAL installed=3.40.1-2+deb12u2 fixed=none`

**Why it matters:** Trivy matched 798 known vulnerabilities in packages of this image (13 have a fixed version available). Image used by: router. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2026-13221, https://avd.aquasec.com/nvd/cve-2026-42496, https://avd.aquasec.com/nvd/cve-2026-8376, https://avd.aquasec.com/nvd/cve-2023-45853, https://avd.aquasec.com/nvd/cve-2025-7458

#### 🔴 `F-V001-885cc6c80e` — Image has known vulnerabilities (47 CRITICAL, 92 HIGH, 146 MEDIUM, 55 LOW)

- **Resource:** image `fortiphyd/grfics-scadalts:latest`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `47 CRITICAL, 92 HIGH, 146 MEDIUM, 55 LOW` — scanner trivy v0.68.2
  - `jar/org.apache.derby:derby` = `CVE-2015-1832 CRITICAL installed=10.6.1.0 fixed=10.12.1.1`
  - `jar/org.springframework:spring-web` = `CVE-2016-1000027 CRITICAL installed=4.3.16.RELEASE fixed=6.0.0`
  - `jar/commons-fileupload:commons-fileupload` = `CVE-2016-1000031 CRITICAL installed=1.3.2 fixed=1.3.3`
  - `jar/com.fasterxml.jackson.core:jackson-databind` = `CVE-2017-15095 CRITICAL installed=2.8.2 fixed=2.8.11, 2.9.4, 2.6.7.3, 2.7.9.2`
  - `jar/com.fasterxml.jackson.core:jackson-databind` = `CVE-2017-17485 CRITICAL installed=2.8.2 fixed=2.9.4, 2.8.11, 2.7.9.2`

**Why it matters:** Trivy matched 340 known vulnerabilities in packages of this image (229 have a fixed version available). Image used by: HMI. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2015-1832, https://avd.aquasec.com/nvd/cve-2016-1000027, https://avd.aquasec.com/nvd/cve-2016-1000031, https://avd.aquasec.com/nvd/cve-2017-15095, https://avd.aquasec.com/nvd/cve-2017-17485

#### 🔴 `F-V001-e3f7e95629` — Image has known vulnerabilities (7 CRITICAL, 157 HIGH, 246 MEDIUM, 278 LOW, 8 UNKNOWN)

- **Resource:** image `fortiphyd/grfics-simulation:latest`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `7 CRITICAL, 157 HIGH, 246 MEDIUM, 278 LOW, 8 UNKNOWN` — scanner trivy v0.68.2
  - `debian/openssl` = `CVE-2026-31789 CRITICAL installed=3.0.16-1~deb12u1 fixed=3.0.19-1~deb12u2`
  - `debian/libssl3` = `CVE-2026-31789 CRITICAL installed=3.0.16-1~deb12u1 fixed=3.0.19-1~deb12u2`
  - `debian/libgnutls30` = `CVE-2026-33845 CRITICAL installed=3.7.9-2+deb12u4 fixed=3.7.9-2+deb12u7`
  - `debian/libgnutls30` = `CVE-2026-42010 CRITICAL installed=3.7.9-2+deb12u4 fixed=3.7.9-2+deb12u7`
  - `debian/zlib1g` = `CVE-2023-45853 CRITICAL installed=1:1.2.13.dfsg-1 fixed=none`

**Why it matters:** Trivy matched 696 known vulnerabilities in packages of this image (144 have a fixed version available). Image used by: simulation. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2026-31789, https://avd.aquasec.com/nvd/cve-2026-31789, https://avd.aquasec.com/nvd/cve-2026-33845, https://avd.aquasec.com/nvd/cve-2026-42010, https://avd.aquasec.com/nvd/cve-2023-45853

#### 🔴 `F-V001-9e8f54fed8` — Image has known vulnerabilities (36 CRITICAL, 704 HIGH, 2175 MEDIUM, 1218 LOW, 8 UNKNOWN)

- **Resource:** image `fortiphyd/grfics-workstation:latest`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `36 CRITICAL, 704 HIGH, 2175 MEDIUM, 1218 LOW, 8 UNKNOWN` — scanner trivy v0.68.2
  - `gobinary/github.com/go-git/go-git/v5` = `CVE-2023-49569 CRITICAL installed=v5.4.2 fixed=5.11.0`
  - `gobinary/github.com/go-git/go-git/v5` = `CVE-2023-49569 CRITICAL installed=v5.4.2 fixed=5.11.0`
  - `gobinary/github.com/go-git/go-git/v5` = `CVE-2023-49569 CRITICAL installed=v5.4.2 fixed=5.11.0`
  - `gobinary/github.com/go-git/go-git/v5` = `CVE-2023-49569 CRITICAL installed=v5.4.2 fixed=5.11.0`
  - `gobinary/stdlib` = `CVE-2024-24790 CRITICAL installed=v1.21.6 fixed=1.21.11, 1.22.4`

**Why it matters:** Trivy matched 4141 known vulnerabilities in packages of this image (656 have a fixed version available). Image used by: EWS. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2023-49569, https://avd.aquasec.com/nvd/cve-2023-49569, https://avd.aquasec.com/nvd/cve-2023-49569, https://avd.aquasec.com/nvd/cve-2023-49569, https://avd.aquasec.com/nvd/cve-2024-24790


## 9. Remediation recommendations

1. Docker socket is mounted into the container: Remove the socket mount. If the service needs Docker metadata (e.g. a version/status page), give it a filtered read-only proxy such as tecnativa/docker-socket-proxy with POST=0 and only the needed API sections.
2. Image has known vulnerabilities (4 CRITICAL, 144 HIGH, 201 MEDIUM, 119 LOW, 4 UNKNOWN): Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.
3. Image has known vulnerabilities (85 CRITICAL, 1319 HIGH, 2796 MEDIUM, 1247 LOW, 187 UNKNOWN): Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.
4. Image has known vulnerabilities (55 CRITICAL, 1544 HIGH, 6197 MEDIUM, 2083 LOW, 121 UNKNOWN): Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.
5. Image has known vulnerabilities (5 CRITICAL, 190 HIGH, 354 MEDIUM, 247 LOW, 2 UNKNOWN): Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.
6. Image has known vulnerabilities (47 CRITICAL, 92 HIGH, 146 MEDIUM, 55 LOW): Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.
7. Image has known vulnerabilities (7 CRITICAL, 157 HIGH, 246 MEDIUM, 278 LOW, 8 UNKNOWN): Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.
8. Image has known vulnerabilities (36 CRITICAL, 704 HIGH, 2175 MEDIUM, 1218 LOW, 8 UNKNOWN): Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.


## 10. Limitations and unknowns

- Metadata-only assessment: no runtime behaviour, network traffic or in-container files were inspected, and no active scanning was performed.
- Image vulnerabilities come from Trivy's database at scan time; exploitability depends on whether the vulnerable code is reachable, which was not tested.
- Findings reflect the Docker state at the snapshot time only; historical runs are not evidence of current state.
- Trivy reported zero vulnerabilities for: fortiphyd/grfics-attacker:latest. This can mean the image is clean OR that Trivy does not support the image's OS/package manager (e.g. Kali Linux); treat these as 'not assessed' until verified.


**Errors / notes during the run:**

- agent: Could not parse the model's final answer: 1 validation error for AgentAssessment   Invalid JSON: EOF while parsing a list at line 1 column 1085 [type=json_invalid, input_value='{"name": "record_contain..."CRITICAL 7, HIGH 157"}', input_type=str]     For further information visit https://errors.pydantic.dev/2.14/v/json_invalid \| partial assessment built from 6 recorded container sections


## 11. Execution metrics

| Metric | Value |
|---|---|
| Duration (total / collect / scan / agent) | 1503.51s / 0.29s / 22.01s / 1480.24s |
| Tool calls (total / by agent / blocked) | 497 / 35 / 0 |
| Model requests | 36 |
| Tokens (in / out / total) | 1334060 / 36108 / 1370168 |


**MCP servers:**

| Server | Role | Version | Connected | Approved tools |
|---|---|---|---|---|
| docker | docker_inspection | docker-mcp-server==2.2.7 | yes | container_list, container_inspect, image_list, image_inspect, image_history, network_list, network_inspect, volume_list, volume_inspect, system_info, system_version |
| trivy | image_scanner | v0.68.2 | yes | scan_image, findings_list, findings_get, trivy_version |


**Tool calls by name:** `docker.container_inspect`×7, `docker.container_list`×2, `docker.image_inspect`×7, `docker.image_list`×1, `docker.network_list`×1, `docker.system_version`×1, `docker.volume_list`×1, `harness.record_container_section`×6, `trivy.findings_list`×455, `trivy.scan_image`×15, `trivy.trivy_version`×1
