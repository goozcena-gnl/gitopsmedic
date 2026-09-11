# Demo script

Requires Python 3.11+, Conftest, reviewed policies, and Trivy for APPLY. Missing required tooling blocks the demo; no bypass is provided. `nginx:1.27.5` below is an example operator input, not an image-security attestation.

1. `make PYTHON=python3 scan` — show normalized findings; HIGH/CRITICAL findings cause a nonzero exit.
2. `make PYTHON=python3 propose REPLACEMENT_IMAGE=nginx:1.27.5` — show deterministic remediation diff and gate results; proposal/log/temp files may be written.
3. Explain that the source file is still unchanged.
4. `make PYTHON=python3 demo REPLACEMENT_IMAGE=nginx:1.27.5` — automatically supplies the token for a temporary copied target when all gates PASS. This simulates approval; no human approval action is captured. For the actual target, review candidate/target and invoke the separate `apply ... --approve <proposal_id>` command.
5. `make PYTHON=python3 eval` — show deterministic evaluation results, not a security score.
6. Optional: `docker compose --profile ai up -d ollama`, `docker compose --profile ai exec ollama ollama pull qwen3:4b`, then `make PYTHON=python3 demo-llm REPLACEMENT_IMAGE=nginx:1.27.5`.
7. Optional observability: `docker compose --profile observability up -d lgtm`, install the `otel` extra, export `OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318`, and rerun the demo.

The original P0 implementation run was BLOCKED because Conftest was absent; Trivy and the built-in gate passed. A later independent verification installed the real tools and completed the hardened demo successfully. See [validation](../VALIDATION.md).
