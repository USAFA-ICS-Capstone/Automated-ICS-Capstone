# Deterministic Security Assessment — `run-20261112-204018-6ebf`

**Status:** completed · **Overall risk:** CRITICAL (highest severity found) · **Generated:** 2026-11-12 20:54 UTC

**Source:** rules + Trivy only, no AI · **Snapshot:** `snap-ecbca778feccaad2` · **Agent model in this run:** `local-vllm` (see agent_report.md)

**Manifest:** `manifest.json` · sha256 `ce5251759b6752a47e2e5a43d631bf6c4f0d60bfc50098f6c7bd8880e2d785cf` · config `2b5d9075e2b91772dd6d433ed44342992f2f0f725e9d661412c6f2639743c955`

## 1. Assessment summary

Deterministic checks (rules and Trivy) produced 77 findings (1 critical, 0 high, 25 medium, 42 low, 9 info). No AI was involved in this report.

**Objective:** Assess the security posture of the Docker environment hosting a containerized industrial control system (ICS) lab. Identify container misconfigurations, risky network exposure, missing resource limits, and known image vulnerabilities. Prioritise risks by their impact on an OT environment and give concrete, evidence-based remediation for defenders.

| Critical | High | Medium | Low | Info |
|---|---|---|---|---|
| 1 | 0 | 25 | 42 | 9 |


## 2. Docker environment overview

- Docker engine: 29.7.2 (Docker Desktop 4.88.1 (237512))
- Docker API endpoint: `unix:///var/run/docker.sock` (full Docker access)
- Snapshot captured: 2026-11-12 20:40:18 UTC
- Containers: 8 (8 running) · Images: 13 · Networks: 7 · Volumes: 24
- Images with known vulnerabilities: 0 · Total vulnerabilities: 


## 3. Container inventory

| Container | Image | State | User | Privileged | Networks | Published ports | Findings |
|---|---|---|---|---|---|---|---|
| EWS | fortiphyd/grfics-workstation | running | root | no | grficsv3_a-grfics-admin, grficsv3_b-ics-net | 0.0.0.0:6080->6080/tcp | 10 |
| HMI | fortiphyd/grfics-scadalts | running | (default: root) | no | grficsv3_a-grfics-admin, grficsv3_c-dmz-net | 0.0.0.0:6081->8080/tcp | 10 |
| caldera | fortiphyd/grfics-caldera | running | (default: root) | no | grficsv3_a-grfics-admin, grficsv3_c-dmz-net | 0.0.0.0:8888->8888/tcp | 7 |
| docker-audit-agent-run-20261112-204017 | docker-audit-agent:latest | running | 10001:10001 | no | docker-audit-agent_default, grficsv3_a-grfics-admin, grficsv3_c-dmz-net | - | 0 |
| kali | fortiphyd/grfics-attacker | running | root | no | grficsv3_a-grfics-admin, grficsv3_c-dmz-net | 0.0.0.0:6088->6080/tcp | 10 |
| plc | fortiphyd/grfics-plc | running | (default: root) | no | grficsv3_a-grfics-admin, grficsv3_b-ics-net | 0.0.0.0:8080->8080/tcp | 9 |
| router | fortiphyd/grfics-router | running | (default: root) | no | grficsv3_a-grfics-admin, grficsv3_b-ics-net, grficsv3_c-dmz-net | 0.0.0.0:51820->51820/udp | 10 |
| simulation | fortiphyd/grfics-simulation | running | (default: root) | no | grficsv3_a-grfics-admin, grficsv3_b-ics-net | 0.0.0.0:80->80/tcp | 10 |


## 4. Image inventory

| Image | ID | Digest | Size (MB) | Used by | Scan | Vulnerabilities |
|---|---|---|---|---|---|---|
| fortiphyd/grfics-workstation:latest | 0e9f4e94459b | fortiphyd/grfics-workstation@sha256:0e9f | 1851.2 | EWS | not scanned | - |
| docker-audit-agent:latest | 40fd44cbb153 | docker-audit-agent@sha256:40fd44cbb15390 | 401.1 | docker-audit-agent-run-20261112-204017 | not scanned | - |
| fortiphyd/grfics-attacker:latest | 6cd239bfad70 | fortiphyd/grfics-attacker@sha256:6cd239b | 1678.3 | kali | not scanned | - |
| fortiphyd/grfics-plc:latest | 7397c8440578 | fortiphyd/grfics-plc@sha256:7397c8440578 | 356.8 | plc | not scanned | - |
| fortiphyd/grfics-scadalts:latest | 83f3f576e769 | fortiphyd/grfics-scadalts@sha256:83f3f57 | 568.2 | HMI | not scanned | - |
| fortiphyd/grfics-router:latest | 9b9a167e5c78 | fortiphyd/grfics-router@sha256:9b9a167e5 | 74.8 | router | not scanned | - |
| fortiphyd/grfics-caldera:latest | a7a3edc9ef16 | fortiphyd/grfics-caldera@sha256:a7a3edc9 | 2603.5 | caldera | not scanned | - |
| fortiphyd/grfics-simulation:latest | ed3517811da2 | fortiphyd/grfics-simulation@sha256:ed351 | 603.5 | simulation | not scanned | - |


## 5. Network configuration

| Network | Driver | Internal | Subnets | Containers |
|---|---|---|---|---|
| bridge | bridge | no | 172.17.0.0/16 | - |
| docker-audit-agent_default | bridge | no | 172.22.0.0/16 | docker-audit-agent-run-20261112-204017 |
| grficsv3_a-grfics-admin | bridge | no | 172.18.0.0/16 | EWS, HMI, caldera, docker-audit-agent-run-20261112-204017, kali, plc, router, simulation |
| grficsv3_b-ics-net | bridge | no | 192.168.95.0/24 | EWS, plc, router, simulation |
| grficsv3_c-dmz-net | bridge | no | 192.168.90.0/24 | HMI, caldera, docker-audit-agent-run-20261112-204017, kali, router |
| host | host | no | - | - |
| none | null | no | - | - |


## 6. Prioritized findings

Ordered by severity; within a severity, running resources and configuration issues first.

| # | Severity | Finding | Resource |
|---|---|---|---|
| 1 | critical | `F-C008-4e4e3d85bf` Docker socket is mounted into the container | simulation |
| 2 | medium | `F-C002-d80b04d8a8` Container adds dangerous capabilities: NET_ADMIN | EWS |
| 3 | medium | `F-C003-ce9491fbed` Container runs as root | EWS |
| 4 | medium | `F-C002-5eb6097b7e` Container adds dangerous capabilities: NET_ADMIN | HMI |
| 5 | medium | `F-C003-23311c45ba` Container runs as root | HMI |
| 6 | medium | `F-C003-969864a9c2` Container runs as root | caldera |
| 7 | medium | `F-C002-4e96c462d7` Container adds dangerous capabilities: NET_ADMIN | kali |
| 8 | medium | `F-C003-5a6b64627b` Container runs as root | kali |
| 9 | medium | `F-C002-404b69a37d` Container adds dangerous capabilities: NET_ADMIN | plc |
| 10 | medium | `F-C003-5d801fb585` Container runs as root | plc |
| 11 | medium | `F-C002-9281fed2c0` Container adds dangerous capabilities: NET_ADMIN, NET_RAW | router |
| 12 | medium | `F-C003-243f2143e9` Container runs as root | router |
| 13 | medium | `F-N003-4385fe0763` IP forwarding enabled inside the container | router |
| 14 | medium | `F-C002-f182dc7f0e` Container adds dangerous capabilities: NET_ADMIN | simulation |
| 15 | medium | `F-C003-20e6282297` Container runs as root | simulation |


## 7. Security misconfigurations (77)

Confirmed by deterministic rules. Each finding lists the exact Docker field that supports it.

#### 🔴 `F-C008-4e4e3d85bf` — Docker socket is mounted into the container

- **Resource:** container `simulation`
- **Category:** filesystem · **Severity:** critical · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Mounts` = `/var/run/docker.sock -> /var/run/docker.sock (rw)` — even a read-only mount of the socket allows full API use

**Why it matters:** The Docker API socket grants full control of the Docker daemon: anyone who controls this container can start a privileged container that mounts the host filesystem, i.e. root on the host and control of every ICS component. Mounting it ':ro' does NOT help - it only makes the socket file read-only, not the API.

**Remediation:** Remove the socket mount. If the service needs Docker metadata (e.g. a version/status page), give it a filtered read-only proxy such as tecnativa/docker-socket-proxy with POST=0 and only the needed API sections.

#### 🟡 `F-C002-d80b04d8a8` — Container adds dangerous capabilities: NET_ADMIN

- **Resource:** container `EWS`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapAdd` = `NET_ADMIN` — can reconfigure interfaces, routes and firewall rules

**Why it matters:** Added capabilities widen what a compromised process can do to the host kernel and network. In an OT lab, NET_ADMIN/NET_RAW on hosts attached to the process network allow traffic manipulation between PLCs and HMIs.

**Remediation:** Remove capabilities that are not strictly required. Start from `cap_drop: [ALL]` and add back only what the service needs; if NET_ADMIN is only used at start-up (e.g. to add routes), configure networking outside the container instead.

#### 🟡 `F-C003-ce9491fbed` — Container runs as root

- **Resource:** container `EWS`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `root` — Config.User

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C002-5eb6097b7e` — Container adds dangerous capabilities: NET_ADMIN

- **Resource:** container `HMI`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapAdd` = `NET_ADMIN` — can reconfigure interfaces, routes and firewall rules

**Why it matters:** Added capabilities widen what a compromised process can do to the host kernel and network. In an OT lab, NET_ADMIN/NET_RAW on hosts attached to the process network allow traffic manipulation between PLCs and HMIs.

**Remediation:** Remove capabilities that are not strictly required. Start from `cap_drop: [ALL]` and add back only what the service needs; if NET_ADMIN is only used at start-up (e.g. to add routes), configure networking outside the container instead.

#### 🟡 `F-C003-23311c45ba` — Container runs as root

- **Resource:** container `HMI`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C003-969864a9c2` — Container runs as root

- **Resource:** container `caldera`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C002-4e96c462d7` — Container adds dangerous capabilities: NET_ADMIN

- **Resource:** container `kali`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapAdd` = `NET_ADMIN` — can reconfigure interfaces, routes and firewall rules

**Why it matters:** Added capabilities widen what a compromised process can do to the host kernel and network. In an OT lab, NET_ADMIN/NET_RAW on hosts attached to the process network allow traffic manipulation between PLCs and HMIs.

**Remediation:** Remove capabilities that are not strictly required. Start from `cap_drop: [ALL]` and add back only what the service needs; if NET_ADMIN is only used at start-up (e.g. to add routes), configure networking outside the container instead.

#### 🟡 `F-C003-5a6b64627b` — Container runs as root

- **Resource:** container `kali`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `root` — Config.User

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C002-404b69a37d` — Container adds dangerous capabilities: NET_ADMIN

- **Resource:** container `plc`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapAdd` = `NET_ADMIN` — can reconfigure interfaces, routes and firewall rules

**Why it matters:** Added capabilities widen what a compromised process can do to the host kernel and network. In an OT lab, NET_ADMIN/NET_RAW on hosts attached to the process network allow traffic manipulation between PLCs and HMIs.

**Remediation:** Remove capabilities that are not strictly required. Start from `cap_drop: [ALL]` and add back only what the service needs; if NET_ADMIN is only used at start-up (e.g. to add routes), configure networking outside the container instead.

#### 🟡 `F-C003-5d801fb585` — Container runs as root

- **Resource:** container `plc`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C002-9281fed2c0` — Container adds dangerous capabilities: NET_ADMIN, NET_RAW

- **Resource:** container `router`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapAdd` = `NET_ADMIN` — can reconfigure interfaces, routes and firewall rules
  - `HostConfig.CapAdd` = `NET_RAW` — can craft raw packets (spoofing, ARP poisoning on the ICS segment)

**Why it matters:** Added capabilities widen what a compromised process can do to the host kernel and network. In an OT lab, NET_ADMIN/NET_RAW on hosts attached to the process network allow traffic manipulation between PLCs and HMIs.

**Remediation:** Remove capabilities that are not strictly required. Start from `cap_drop: [ALL]` and add back only what the service needs; if NET_ADMIN is only used at start-up (e.g. to add routes), configure networking outside the container instead.

#### 🟡 `F-C003-243f2143e9` — Container runs as root

- **Resource:** container `router`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-N003-4385fe0763` — IP forwarding enabled inside the container

- **Resource:** container `router`
- **Category:** network-segmentation · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Sysctls.net.ipv4.ip_forward` = `1`

**Why it matters:** The container routes packets between its interfaces. Expected for a router/firewall container, but it makes this container a critical segmentation control: its rule set and hardening determine whether zones are actually isolated.

**Remediation:** Confirm this container is the intended router; harden and monitor it, restrict its management interface, and disable forwarding elsewhere.

#### 🟡 `F-C002-f182dc7f0e` — Container adds dangerous capabilities: NET_ADMIN

- **Resource:** container `simulation`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapAdd` = `NET_ADMIN` — can reconfigure interfaces, routes and firewall rules

**Why it matters:** Added capabilities widen what a compromised process can do to the host kernel and network. In an OT lab, NET_ADMIN/NET_RAW on hosts attached to the process network allow traffic manipulation between PLCs and HMIs.

**Remediation:** Remove capabilities that are not strictly required. Start from `cap_drop: [ALL]` and add back only what the service needs; if NET_ADMIN is only used at start-up (e.g. to add routes), configure networking outside the container instead.

#### 🟡 `F-C003-20e6282297` — Container runs as root

- **Resource:** container `simulation`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-N002-f7651bfcce` — Container bridges multiple networks

- **Resource:** container `EWS`
- **Category:** network-segmentation · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `NetworkSettings.Networks.grficsv3_a-grfics-admin` = `172.18.0.6`
  - `NetworkSettings.Networks.grficsv3_b-ics-net` = `192.168.95.5`

**Why it matters:** A container attached to several networks is a potential bridge between segmentation zones (e.g. DMZ <-> process network). If it is compromised, an attacker can pivot across zones that the network design intends to keep apart. Whether this is intended (a router/firewall) needs human review.

**Remediation:** Attach the container only to the networks it must serve. Route inter-zone traffic through a dedicated, hardened firewall container and keep management networks separate from ICS process networks.

#### 🟡 `F-S001-2f727430b4` — Credential-like environment variables: VNC_PASSWORD

- **Resource:** container `EWS`
- **Category:** secrets-hygiene · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.Env` = `VNC_PASSWORD` — variable name; value not reported

**Why it matters:** Secrets passed as environment variables are visible to anyone who can inspect the container (docker inspect, /proc/<pid>/environ) and often leak into logs and crash dumps. The name alone indicates a likely credential.

**Remediation:** Use Docker secrets / mounted secret files with restricted permissions, and rotate any credential that was exposed via the environment.

#### 🟡 `F-N002-5a983dd79f` — Container bridges multiple networks

- **Resource:** container `HMI`
- **Category:** network-segmentation · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `NetworkSettings.Networks.grficsv3_a-grfics-admin` = `172.18.0.8`
  - `NetworkSettings.Networks.grficsv3_c-dmz-net` = `192.168.90.107`

**Why it matters:** A container attached to several networks is a potential bridge between segmentation zones (e.g. DMZ <-> process network). If it is compromised, an attacker can pivot across zones that the network design intends to keep apart. Whether this is intended (a router/firewall) needs human review.

**Remediation:** Attach the container only to the networks it must serve. Route inter-zone traffic through a dedicated, hardened firewall container and keep management networks separate from ICS process networks.

#### 🟡 `F-S001-240b49b63f` — Credential-like environment variables: MYSQL_PASSWORD, MYSQL_ROOT_PASSWORD, TOMCAT_PASSWORD

- **Resource:** container `HMI`
- **Category:** secrets-hygiene · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.Env` = `MYSQL_PASSWORD` — variable name; value not reported
  - `Config.Env` = `MYSQL_ROOT_PASSWORD` — variable name; value not reported
  - `Config.Env` = `TOMCAT_PASSWORD` — variable name; value not reported

**Why it matters:** Secrets passed as environment variables are visible to anyone who can inspect the container (docker inspect, /proc/<pid>/environ) and often leak into logs and crash dumps. The name alone indicates a likely credential.

**Remediation:** Use Docker secrets / mounted secret files with restricted permissions, and rotate any credential that was exposed via the environment.

#### 🟡 `F-N002-1e8a2ed9c0` — Container bridges multiple networks

- **Resource:** container `caldera`
- **Category:** network-segmentation · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `NetworkSettings.Networks.grficsv3_a-grfics-admin` = `172.18.0.3`
  - `NetworkSettings.Networks.grficsv3_c-dmz-net` = `192.168.90.250`

**Why it matters:** A container attached to several networks is a potential bridge between segmentation zones (e.g. DMZ <-> process network). If it is compromised, an attacker can pivot across zones that the network design intends to keep apart. Whether this is intended (a router/firewall) needs human review.

**Remediation:** Attach the container only to the networks it must serve. Route inter-zone traffic through a dedicated, hardened firewall container and keep management networks separate from ICS process networks.

#### 🟡 `F-N002-3ee285a841` — Container bridges multiple networks

- **Resource:** container `kali`
- **Category:** network-segmentation · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `NetworkSettings.Networks.grficsv3_a-grfics-admin` = `172.18.0.4`
  - `NetworkSettings.Networks.grficsv3_c-dmz-net` = `192.168.90.6`

**Why it matters:** A container attached to several networks is a potential bridge between segmentation zones (e.g. DMZ <-> process network). If it is compromised, an attacker can pivot across zones that the network design intends to keep apart. Whether this is intended (a router/firewall) needs human review.

**Remediation:** Attach the container only to the networks it must serve. Route inter-zone traffic through a dedicated, hardened firewall container and keep management networks separate from ICS process networks.

#### 🟡 `F-S001-126559871a` — Credential-like environment variables: VNC_PASSWORD

- **Resource:** container `kali`
- **Category:** secrets-hygiene · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.Env` = `VNC_PASSWORD` — variable name; value not reported

**Why it matters:** Secrets passed as environment variables are visible to anyone who can inspect the container (docker inspect, /proc/<pid>/environ) and often leak into logs and crash dumps. The name alone indicates a likely credential.

**Remediation:** Use Docker secrets / mounted secret files with restricted permissions, and rotate any credential that was exposed via the environment.

#### 🟡 `F-N002-080291cb7f` — Container bridges multiple networks

- **Resource:** container `plc`
- **Category:** network-segmentation · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `NetworkSettings.Networks.grficsv3_a-grfics-admin` = `172.18.0.5`
  - `NetworkSettings.Networks.grficsv3_b-ics-net` = `192.168.95.2`

**Why it matters:** A container attached to several networks is a potential bridge between segmentation zones (e.g. DMZ <-> process network). If it is compromised, an attacker can pivot across zones that the network design intends to keep apart. Whether this is intended (a router/firewall) needs human review.

**Remediation:** Attach the container only to the networks it must serve. Route inter-zone traffic through a dedicated, hardened firewall container and keep management networks separate from ICS process networks.

#### 🟡 `F-N002-49a71a7580` — Container bridges multiple networks

- **Resource:** container `router`
- **Category:** network-segmentation · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `NetworkSettings.Networks.grficsv3_a-grfics-admin` = `172.18.0.2`
  - `NetworkSettings.Networks.grficsv3_b-ics-net` = `192.168.95.200`
  - `NetworkSettings.Networks.grficsv3_c-dmz-net` = `192.168.90.200`

**Why it matters:** A container attached to several networks is a potential bridge between segmentation zones (e.g. DMZ <-> process network). If it is compromised, an attacker can pivot across zones that the network design intends to keep apart. Whether this is intended (a router/firewall) needs human review.

**Remediation:** Attach the container only to the networks it must serve. Route inter-zone traffic through a dedicated, hardened firewall container and keep management networks separate from ICS process networks.

#### 🟡 `F-S001-7892b017d8` — Credential-like environment variables: FWUI_SECRET_KEY

- **Resource:** container `router`
- **Category:** secrets-hygiene · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.Env` = `FWUI_SECRET_KEY` — variable name; value not reported

**Why it matters:** Secrets passed as environment variables are visible to anyone who can inspect the container (docker inspect, /proc/<pid>/environ) and often leak into logs and crash dumps. The name alone indicates a likely credential.

**Remediation:** Use Docker secrets / mounted secret files with restricted permissions, and rotate any credential that was exposed via the environment.

#### 🟡 `F-N002-d309dae527` — Container bridges multiple networks

- **Resource:** container `simulation`
- **Category:** network-segmentation · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `NetworkSettings.Networks.grficsv3_a-grfics-admin` = `172.18.0.7`
  - `NetworkSettings.Networks.grficsv3_b-ics-net` = `192.168.95.45`

**Why it matters:** A container attached to several networks is a potential bridge between segmentation zones (e.g. DMZ <-> process network). If it is compromised, an attacker can pivot across zones that the network design intends to keep apart. Whether this is intended (a router/firewall) needs human review.

**Remediation:** Attach the container only to the networks it must serve. Route inter-zone traffic through a dedicated, hardened firewall container and keep management networks separate from ICS process networks.

#### 🔵 `F-C006-c7ef8e1dc4` — no-new-privileges is not set

- **Resource:** container `EWS`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-2080f894d4` — Root filesystem is writable

- **Resource:** container `EWS`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-235463330e` — Ports published on all host interfaces

- **Resource:** container `EWS`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:6080 -> 6080/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-17404924d7` — Missing resource limits: memory, cpu, pids

- **Resource:** container `EWS`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-74e9958669` — no-new-privileges is not set

- **Resource:** container `HMI`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-5e5284b3d8` — Root filesystem is writable

- **Resource:** container `HMI`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-7ce810b10c` — Ports published on all host interfaces

- **Resource:** container `HMI`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:6081 -> 8080/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-806a10d07a` — Missing resource limits: memory, cpu, pids

- **Resource:** container `HMI`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-c47aff7923` — no-new-privileges is not set

- **Resource:** container `caldera`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-ce03660925` — Root filesystem is writable

- **Resource:** container `caldera`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-5ad245ed07` — Ports published on all host interfaces

- **Resource:** container `caldera`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:8888 -> 8888/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-4f79dd1701` — Missing resource limits: memory, cpu, pids

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

#### 🔵 `F-C006-02825f8e1e` — no-new-privileges is not set

- **Resource:** container `kali`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-8abf0baf8d` — Root filesystem is writable

- **Resource:** container `kali`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-41acdae40f` — Ports published on all host interfaces

- **Resource:** container `kali`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:6088 -> 6080/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-6e07309bbc` — Missing resource limits: memory, cpu, pids

- **Resource:** container `kali`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-97bd3e6a74` — no-new-privileges is not set

- **Resource:** container `plc`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-191731940b` — Root filesystem is writable

- **Resource:** container `plc`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-86ef13b1aa` — Ports published on all host interfaces

- **Resource:** container `plc`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:8080 -> 8080/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-303819126c` — Missing resource limits: memory, cpu, pids

- **Resource:** container `plc`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-3fc44992d9` — no-new-privileges is not set

- **Resource:** container `router`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-7dd04fe24f` — Root filesystem is writable

- **Resource:** container `router`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-82ce7c49a6` — Ports published on all host interfaces

- **Resource:** container `router`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:51820 -> 51820/udp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-f35add19c8` — Missing resource limits: memory, cpu, pids

- **Resource:** container `router`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-3a5230d8fe` — no-new-privileges is not set

- **Resource:** container `simulation`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-3df237ffc1` — Root filesystem is writable

- **Resource:** container `simulation`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-9c73e88cd5` — Ports published on all host interfaces

- **Resource:** container `simulation`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:80 -> 80/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-9900ea2863` — Missing resource limits: memory, cpu, pids

- **Resource:** container `simulation`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C010-6f27e7f0bf` — No capabilities are dropped

- **Resource:** container `EWS`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-968d438a2e` — No capabilities are dropped

- **Resource:** container `HMI`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-0073685d5b` — No capabilities are dropped

- **Resource:** container `caldera`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-e47f023f40` — No capabilities are dropped

- **Resource:** container `kali`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-d182d41cb2` — No capabilities are dropped

- **Resource:** container `plc`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-d8070d267f` — No capabilities are dropped

- **Resource:** container `router`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-5a95b76b2f` — No capabilities are dropped

- **Resource:** container `simulation`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### ⚪ `F-R002-5874021eef` — No restart policy

- **Resource:** container `EWS`
- **Category:** resources · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.RestartPolicy.Name` = `no`

**Why it matters:** The container will not be restarted automatically after a crash or host reboot, which may affect availability of the simulated process.

**Remediation:** Use `restart: unless-stopped` for services that must stay available.

#### ⚪ `F-R002-ec8808c861` — No restart policy

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
  - `Containers` = `docker-audit-agent-run-20261112-204017`

**Why it matters:** Containers on this network can open outbound connections through the host. ICS process networks normally should not reach the internet.

**Remediation:** For process/control networks set `internal: true` and provide any required external access through an explicit, monitored gateway.

#### ⚪ `F-N005-9e52cae48b` — Network 'grficsv3_a-grfics-admin' is not internal (has external egress)

- **Resource:** network `grficsv3_a-grfics-admin`
- **Category:** network-segmentation · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Internal` = `False`
  - `Driver` = `bridge`
  - `Containers` = `EWS, HMI, caldera, docker-audit-agent-run-20261112-204017, kali, plc, router, simulation`

**Why it matters:** Containers on this network can open outbound connections through the host. ICS process networks normally should not reach the internet.

**Remediation:** For process/control networks set `internal: true` and provide any required external access through an explicit, monitored gateway.

#### ⚪ `F-N005-91e530036f` — Network 'grficsv3_b-ics-net' is not internal (has external egress)

- **Resource:** network `grficsv3_b-ics-net`
- **Category:** network-segmentation · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Internal` = `False`
  - `Driver` = `bridge`
  - `Containers` = `EWS, plc, router, simulation`

**Why it matters:** Containers on this network can open outbound connections through the host. ICS process networks normally should not reach the internet.

**Remediation:** For process/control networks set `internal: true` and provide any required external access through an explicit, monitored gateway.

#### ⚪ `F-N005-cb1fa4ba80` — Network 'grficsv3_c-dmz-net' is not internal (has external egress)

- **Resource:** network `grficsv3_c-dmz-net`
- **Category:** network-segmentation · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Internal` = `False`
  - `Driver` = `bridge`
  - `Containers` = `HMI, caldera, docker-audit-agent-run-20261112-204017, kali, router`

**Why it matters:** Containers on this network can open outbound connections through the host. ICS process networks normally should not reach the internet.

**Remediation:** For process/control networks set `internal: true` and provide any required external access through an explicit, monitored gateway.

#### ⚪ `F-R002-03c00958d9` — No restart policy

- **Resource:** container `kali`
- **Category:** resources · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.RestartPolicy.Name` = `no`

**Why it matters:** The container will not be restarted automatically after a crash or host reboot, which may affect availability of the simulated process.

**Remediation:** Use `restart: unless-stopped` for services that must stay available.

#### ⚪ `F-R002-b9cfcbb66d` — No restart policy

- **Resource:** container `plc`
- **Category:** resources · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.RestartPolicy.Name` = `no`

**Why it matters:** The container will not be restarted automatically after a crash or host reboot, which may affect availability of the simulated process.

**Remediation:** Use `restart: unless-stopped` for services that must stay available.

#### ⚪ `F-R002-6cc28ad018` — No restart policy

- **Resource:** container `simulation`
- **Category:** resources · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.RestartPolicy.Name` = `no`

**Why it matters:** The container will not be restarted automatically after a crash or host reboot, which may affect availability of the simulated process.

**Remediation:** Use `restart: unless-stopped` for services that must stay available.


## 8. Known image vulnerabilities

Reported by Trivy; CVE IDs, severities and versions are copied verbatim from the scanner.


## 9. Remediation recommendations

1. Docker socket is mounted into the container: Remove the socket mount. If the service needs Docker metadata (e.g. a version/status page), give it a filtered read-only proxy such as tecnativa/docker-socket-proxy with POST=0 and only the needed API sections.
2. Container adds dangerous capabilities: NET_ADMIN: Remove capabilities that are not strictly required. Start from `cap_drop: [ALL]` and add back only what the service needs; if NET_ADMIN is only used at start-up (e.g. to add routes), configure networking outside the container instead.
3. Container runs as root: Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.


## 10. Limitations and unknowns

- Metadata-only assessment: no runtime behaviour, network traffic or in-container files were inspected, and no active scanning was performed.
- Image vulnerabilities come from Trivy's database at scan time; exploitability depends on whether the vulnerable code is reachable, which was not tested.
- Findings reflect the Docker state at the snapshot time only; historical runs are not evidence of current state.


## 11. Execution metrics

| Metric | Value |
|---|---|
| Duration (total / collect / scan / agent) | 864.1s / 0.28s / 0.0s / 863.29s |
| Tool calls (total / by agent / blocked) | 35 / 29 / 0 |
| Model requests | 30 |
| Tokens (in / out / total) | 882823 / 21658 / 904481 |


**MCP servers:**

| Server | Role | Version | Connected | Approved tools |
|---|---|---|---|---|
| docker | docker_inspection | docker-mcp-server==2.2.7 | yes | container_list, container_inspect, image_list, image_inspect, image_history, network_list, network_inspect, volume_list, volume_inspect, system_info, system_version |
| trivy | image_scanner | v0.68.2 | yes | scan_image, findings_list, findings_get, trivy_version |


**Tool calls by name:** `docker.container_inspect`×7, `docker.container_list`×2, `docker.image_list`×1, `docker.network_list`×1, `docker.system_version`×1, `docker.volume_list`×1, `harness.record_container_section`×7, `trivy.findings_list`×7, `trivy.scan_image`×7, `trivy.trivy_version`×1
