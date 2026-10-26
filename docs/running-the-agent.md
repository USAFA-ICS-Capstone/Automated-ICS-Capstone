# Running the agent in the GRFICS environment

Step-by-step runbook for one experiment: reset the GRFICSv3 lab to the clean
baseline, run the agent, and read what it found and missed. Everything here runs
on the Mac, from the repository root. For background on each step see the
README (sections 3, 4, 10, 15) and `docs/grfics-integration-notes.md`.

Paths below assume this layout:

```text
~/SeniorYear/Capstone/
├── Automated-ICS-Capstone/   this repository
└── GRFICSv3/                 GRFICSv3 checkout (images already pulled)
```

## What a run does

1. The deterministic checks (20 rules + Trivy) assess the lab. This is the
   answer key; the agent never sees it.
2. The agent (`DockerSecurityAssessmentAgent`, prompt v4) gets only the
   objective and the read-only MCP tools. It decides what to inspect and scan,
   and reports its own findings.
3. Its findings are validated against the real Docker data and compared with
   the answer key.
4. Three reports are written to `outputs/<RUN_ID>/`: `agent_report.md`,
   `deterministic_report.md` and `comparison.md` (each with a `.json` twin).

## One-time setup

Skip anything already done on this machine.

| What | Command | Check |
|---|---|---|
| Python environment | `uv sync` | `ls .venv/bin/docker-audit` |
| Local model (32k context) | `uv run docker-audit models --provider ollama --create-variant qwen3:14b` | `ollama list` shows `qwen3:14b-ctx32k` |
| Trivy plugin + vulnerability DB | `uv run docker-audit setup` | `doctor` shows the Trivy DB as OK |
| Trivy Java DB (needed for Java images such as Caldera) | `trivy image --download-java-db-only` | no `failed to scan project` errors in step 6 |
| GRFICS images | in `GRFICSv3/`: `docker compose -f docker-compose.yml -f ../Automated-ICS-Capstone/deploy/grfics/docker-compose.macos.yml pull` | `docker images \| grep fortiphyd` shows 7 images |
| Clean baseline | `deploy/grfics/range.sh save clean-v1` (lab running and healthy, nothing changed yet) | `data/range-baselines/clean-v1/` exists |

`clean-v1` already exists on this machine (saved 2026-10-20). Baselines are
write-once: to record a new one, use a new name (`clean-v2`).

## Every experiment

### 1. Start Docker Desktop and Ollama

Open Docker Desktop and wait until it is running. Then check the model:

```bash
curl -s http://localhost:11434/api/tags | grep -o qwen3:14b-ctx32k
```

If nothing is printed, start the Ollama app and check again.

### 2. Prepare the shell

```bash
cd ~/SeniorYear/Capstone/Automated-ICS-Capstone
deactivate 2>/dev/null                            # leave any other project's venv
export GRFICS_DIR=~/SeniorYear/Capstone/GRFICSv3  # range.sh defaults to ~/GRFICSv3
```

Do this in every new terminal.

### 3. Start the read-only Docker API proxy

```bash
docker compose -f deploy/socket-proxy/compose.yml up -d
```

It must be running before the reset: it was running when `clean-v1` was
recorded, and the reset's verification reads Docker through it.

### 4. Reset GRFICS to the clean baseline

```bash
deploy/grfics/range.sh reset clean-v1
```

It removes the lab, restores its volumes, starts it from local images and
verifies it. It must end with:

```text
Range matches baseline clean-v1 (... grficsv3's containers and volumes recreated by the reset)
```

If it reports differences instead, stop and see [Troubleshooting](#troubleshooting).

### 5. Preflight check

```bash
uv run docker-audit doctor --probe
```

Every row must be OK: configuration, the proxy (`filtered=True`), both MCP
servers, the Trivy DB, and the `local-qwen` model (tool-call probe succeeded).

### 6. Run the assessment

```bash
uv run docker-audit assess --model local-qwen --range-baseline clean-v1
```

- `--range-baseline clean-v1` makes the run abort if the lab differs from the
  baseline, and records the baseline in the run's manifest.
- The deterministic part (inventory, rules, Trivy) takes about 1-3 minutes.
  The agent phase can take much longer with a local model: it has up to 60
  turns, 100 tool calls and 3600 seconds (`config/agent.yaml`).
- The command ends with a summary like:

```text
Run run-YYYYMMDD-HHMMSS-xxxx: completed — deterministic risk CRITICAL
Deterministic findings: critical 7, high 1, medium 25, low 42, info 10
Agent (ok): N findings, M rejected · agent risk ...
Comparison: found X/85 deterministic findings (recall ..%, weighted ..%) · missed ...
Deterministic report: outputs/run-.../deterministic_report.md
Agent report:         outputs/run-.../agent_report.md
Comparison:           outputs/run-.../comparison.md
```

To watch what the agent is doing while it runs, use a second terminal:

```bash
docker logs -f docker-audit-socket-proxy                          # each Docker query it makes
tail -f ~/.ollama/logs/server.log | grep -i "chat/completions"    # each model turn
```

### 7. Read the results

```bash
RUN=$(ls -t outputs | head -1)
open outputs/$RUN/comparison.md          # start here: found, missed, scores
open outputs/$RUN/agent_report.md        # what the agent reported, with evidence
open outputs/$RUN/deterministic_report.md
```

Or from the database, for any run:

```bash
uv run docker-audit runs
uv run docker-audit report --run-id <RUN_ID>                       # comparison
uv run docker-audit report --run-id <RUN_ID> --kind agent
uv run docker-audit report --run-id <RUN_ID> --kind deterministic
```

What to look at in `comparison.md`:

| Section | Meaning |
|---|---|
| Scores | recall = deterministic findings the agent found / all of them; weighted recall counts critical 4, high 3, medium 2, low 1, info 0 |
| Missed by the agent | confirmed issues the agent did not report |
| Found by the agent | matched issues, with the agent's severity vs the rule's |
| Outside the rules | validated agent findings no rule covers: review by hand |
| Rejected | agent claims that failed validation (invented resource, field or CVE) |

### 8. See every tool call the agent made

```bash
sqlite3 -header -column data/assessments.db "
  select timestamp, server, tool, status, duration_ms, arguments_json
  from tool_calls
  where run_id = (select run_id from runs order by rowid desc limit 1) and phase = 'agent'
  order by id"
```

`status` is `ok`, `error`, `blocked` (refused by the tool policy) or
`budget_exhausted`. The full conversation is in `data/agent_sessions.db`.

### 9. Compare another model (optional)

Reset before every run, so each model starts from the same lab and is scored
against the same answer key:

```bash
deploy/grfics/range.sh reset clean-v1
uv run docker-audit assess --model local-gpt-oss --range-baseline clean-v1
```

The model must be installed in Ollama and have a profile in
`config/models.yaml`. `openai-primary` needs `OPENAI_API_KEY` in `.env`.

### 10. Shut down

```bash
docker compose -f $GRFICS_DIR/docker-compose.yml \
  -f deploy/grfics/docker-compose.macos.yml -p grficsv3 stop
docker compose -f deploy/socket-proxy/compose.yml stop
```

Nothing is deleted. The next experiment starts again at step 1; the reset in
step 4 brings the lab back to `clean-v1`.

## Rules during the experiment period

Each of these changes the lab or its images, and makes later runs fail the
baseline check or stop being comparable:

- Do not run `docker compose pull`, or `up` without `--pull never`, in `GRFICSv3/`.
- Do not run `docker image prune`, `docker system prune`, or Docker Desktop's
  "Clean / Purge data".
- Do not rebuild GRFICS images.
- Do not delete any Docker volume, including the kept `ics_range_*` and
  `bloodhound_*` volumes: the baseline fingerprint covers all of them.
- Do not start other labs (`ics_range`, BloodHound) on this Docker engine.

## Running the agent in a container instead

Same steps 1-4, then:

```bash
deploy/agent/build.sh                                  # first time, and after code changes
A="docker compose -f deploy/agent/compose.yml run --rm"
$A agent setup                                         # first time: Trivy DB in its volume
$A --entrypoint trivy agent image --download-java-db-only
$A agent doctor --probe
$A agent assess --model local-qwen
```

Leave out `--range-baseline` in the container: the agent's own container is
on the engine during the run, so the baseline check would report it as a
difference. Reports still land in `outputs/` and `data/` on the Mac.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `No docker-compose.yml in GRFICS_DIR=/Users/.../GRFICSv3` | `export GRFICS_DIR=~/SeniorYear/Capstone/GRFICSv3` (step 2) |
| Reset ends with `Range does NOT match baseline clean-v1` | Read the listed differences. A changed image ID: the images changed; save a new baseline (`clean-v2`). An unexpected container: stop the other project (`docker compose -p <project> down`). |
| `Cannot reach Docker proxy` / doctor fails on the proxy | Step 3: `docker compose -f deploy/socket-proxy/compose.yml up -d` |
| `--snapshot replays stored evidence for --no-agent runs only` | The agent needs live Docker. Reset the lab and run live (steps 4 and 6). |
| `VIRTUAL_ENV ... does not match` warning, or `Failed to spawn` | `deactivate` (step 2), then retry |
| Model check fails / cannot reach Ollama | Start Ollama; `curl http://localhost:11434/api/tags` must answer |
| Scan fails with `failed to scan project` | `trivy image --download-java-db-only`, then rerun step 6 |
| Agent status `timeout` or `max_turns` | The model ran out of time or turns: every finding shows as missed. Raise the limits in `config/agent.yaml` (recorded in the manifest), or try a faster model. |
| Agent status `invalid_output` | The model's final answer was not valid JSON. Try `structured_output: native` in its profile or a stronger model. |
