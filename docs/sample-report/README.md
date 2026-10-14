# Sample assessment report

`report.md` and `report.json` are the unmodified output of a real live run:

```bash
uv run docker-audit assess --model local-qwen
```

- Run: `run-20261009-030302-f940` (prompt v3, model `qwen3:14b-ctx32k` on Ollama)
- Target: a locally running ICS range on Docker Desktop (20 containers, 38 images,
  8 networks). This is not GRFICSv3; see the main README, section 15.
- 20 images scanned with Trivy; 227 values redacted; 303 tool calls (302 by the
  collector, 1 by the agent); about 6.4 minutes end to end.

Note: the report contains host paths and container names from the development machine.
Review it before publishing the repository.
