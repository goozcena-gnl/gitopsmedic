# Demo script

1. `make scan` — show normalized findings.
2. `make propose` — show deterministic remediation diff and gate results.
3. Explain that the source file is still unchanged.
4. `make demo` — runs the full flow in a temporary workspace and performs the exact human approval step.
5. `make eval` — show repeatable evaluation score.
6. Optional: `docker compose --profile ai up -d ollama`, `docker compose --profile ai exec ollama ollama pull qwen3:4b`, then `make demo-llm`.
7. Optional observability: `docker compose --profile observability up -d lgtm`, install the `otel` extra, export `OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318`, and rerun the demo.
