# GitOpsMedic

**A local-first CloudOps remediation agent that diagnoses Kubernetes manifest risk, proposes deterministic changes, and requires content-bound approval plus fresh validation before APPLY replaces a target manifest.**

Inspired by the CloudOps pattern in the Onepoint × AWS AgentCore hackathon (Bordeaux, 29 September 2026), but deliberately implemented with a zero-cost/open-source local path.

## Why this exists

Agent demos often give an LLM broad tool access and call that automation. GitOpsMedic demonstrates a stricter platform-engineering pattern:

`READ -> DIAGNOSE -> EXPLAIN -> PROPOSE DIFF -> VALIDATE -> HUMAN APPROVAL -> APPLY`

The model is useful, but never authoritative. **Ollama can explain and prioritize findings; deterministic code owns diagnosis and remediation.**

## Architecture

The deterministic remediator takes the manifest and an optional operator-reviewed digest-pinned replacement image. Built-in checks, Conftest, and Trivy validate the candidate. APPLY recomputes the source/target/candidate digest, checks approval and source freshness, reruns all gates, then uses exclusive temporary-file creation and atomic replacement. Ollama only supplies explanation text. See [architecture](docs/architecture.md).

## MVP features

- Kubernetes `Deployment` JSON analysis with deterministic policy rules.
- Detects weak availability, `:latest` images, missing resource bounds, root execution risk, privilege escalation and writable root filesystems.
- Generates a deterministic candidate and unified diff without touching the source.
- Uses explicit `--replacement-image` operator input; manifest annotations cannot select a replacement.
- Requires built-in, Conftest/Rego, and Trivy gates to PASS; unavailable required gates block APPLY.
- Recomputes full SHA-256 proposal identity at APPLY, binding source hash, absolute target, and candidate.
- SHA-256 stale-proposal protection and apply-time revalidation.
- Optional local Ollama explanation, excluded from candidate generation and authorization.
- JSONL run telemetry; optional OTLP traces.
- Repeatable evaluation scenarios and unit tests.
- GitHub Actions CI with no marketplace checkout action.

## Quick start

Requires Python 3.11+. The core MVP has **zero mandatory Python package dependencies**. The hardened APPLY profile additionally requires reviewed Rego policies plus locally trusted Conftest and Trivy executables whose SHA-256 values are configured with `GITOPSMEDIC_CONFTEST_{PATH,SHA256}` and `GITOPSMEDIC_TRIVY_{PATH,SHA256}`. No missing-tool bypass is provided.

```bash
git clone https://github.com/goozcena-gnl/gitopsmedic.git gitops-medic
cd gitops-medic
make PYTHON=python3 test eval compile
make PYTHON=python3 demo REPLACEMENT_IMAGE=nginx@sha256:6784fb0834aa7dbbe12e3d7471e69c290df3e6ba810dc38b34ae33d3c1c05f7d
```

The image above is an example digest-pinned operator choice, not an attested image recommendation. Versioned tags such as `nginx:1.27.5` are not immutable and remain blocked by the hardened gate. The demo automatically supplies its token for a temporary copied manifest only; it refuses when required gates do not PASS.

### Inspect without changing the source

```bash
make PYTHON=python3 scan
make PYTHON=python3 propose REPLACEMENT_IMAGE=nginx@sha256:6784fb0834aa7dbbe12e3d7471e69c290df3e6ba810dc38b34ae33d3c1c05f7d
```

`scan` returns nonzero for HIGH/CRITICAL findings. `propose` saves a proposal and prints its 64-character `proposal_id`; it exits 2 if any required gate does not PASS. Both commands can write telemetry, and PLAN also writes temporary validation files and a proposal. They preserve the source manifest, not every filesystem path.

The real apply command is intentionally separate:

```bash
PYTHONPATH=src python3 -m gitops_medic apply .gitops-medic/proposals/<proposal_id>.json --approve <proposal_id>
```

## Optional local AI

Ollama is an advisory layer only. The default model is `qwen3:4b`.

```bash
docker compose --profile ai up -d ollama
docker compose --profile ai exec ollama ollama pull qwen3:4b
make demo-llm
```

If Ollama is missing or unavailable, GitOpsMedic falls back to deterministic explanations. This does not relax the required security gates. Pass `REPLACEMENT_IMAGE=<reviewed-image>` to `make demo-llm` as with the deterministic demo.

## Optional observability

```bash
docker compose --profile observability up -d lgtm
python -m pip install -e '.[otel]'
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
make demo
```

Grafana LGTM is intended here for development/demo observability, not as a production architecture.

## Safety model

Normal `apply` requires an explicit approval argument. The temporary demo simulates approval automatically and is not a human-approval audit.

Apply requires all of the following:

1. candidate passes mandatory deterministic policy validation;
2. Conftest with reviewed policies and Trivy both report PASS;
3. stored proposal id, recomputed digest, and operator-supplied approval match;
4. target is a regular file inside the resolved repository root;
5. source SHA-256 is unchanged;
6. candidate passes apply-time revalidation.

Raw model output is never evaluated as code and never sent to a shell.

The P0 pass added negative regressions for proposal tampering, manifest-controlled images, missing gates, host privileges, and temporary-path symlinks. Detailed evidence, assumptions about operator-controlled paths, and remaining limitations are in [security](docs/security.md) and [validation](VALIDATION.md). Serialized safety, diffs, and explanations are not authorization inputs.

## Evaluation

```bash
make PYTHON=python3 eval
```

The included tests cover healthy/insecure states, metadata injection in deterministic diagnosis, unfixable images, tampering, missing/failing scanners, dangerous privileges, filesystem attacks, wrong approvals, stale proposals, and successful APPLY with mocked gate outcomes. Mocked scanners do not establish real scanner compatibility; actual local results are in [VALIDATION.md](VALIDATION.md).

## DevOps Tools Catalog constraint

The project was designed against the `goozcena-gnl/devops-tools-catalog` snapshot on 2026-09-10. External components used or proposed are drawn from that allow-list. Core implementation uses Python standard library code rather than adding an unnecessary agent framework. See `docs/research.md`.

## Portfolio roadmap

- Add YAML input after selecting an allow-listed parser/runtime strategy.
- Add read-only live Kubernetes inventory through an allow-listed MCP server.
- Generate a Git branch/PR instead of updating a working-tree file.
- Extend rules to Terraform/OpenTofu and GitOps drift.
- Add OTel metrics and dashboards for agent runs/tool errors/approval outcomes.
- Add DeepEval model-quality regression while retaining deterministic authorization.
- Add scoped identity and per-tool permissions.

## Limitations

This is a portfolio/hackathon MVP, not a production admission controller. It supports Kubernetes Deployment JSON and opinionated demo remediations, not full Kubernetes schema or Pod Security Standards validation. Explicit image replacement refuses multiple regular containers or any init/ephemeral containers. Approval is content binding, not authentication or signing. Filesystem checks assume an operator-controlled checkout without concurrent hostile writers. It does not claim equivalence with managed AgentCore services.

## License

MIT.
