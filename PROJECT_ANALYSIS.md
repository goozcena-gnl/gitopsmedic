# GitOpsMedic — project selection and portfolio assessment

## Candidate ranking

| Rank | Candidate | Score /100 | Why |
|---:|---|---:|---|
| 1 | **GitOpsMedic** | **94.0** | Best blend of CloudOps, GitOps, Kubernetes, guardrails, security, reproducibility and demo clarity |
| 2 | KubeUpgrade Agent | 90.5 | Excellent CloudOps relevance but narrower than repository-level remediation |
| 3 | SRE Triage Agent | 88.5 | Strong SRE/observability learning, less feasible for a one-day credible end-to-end demo |
| 4 | DocDrift Agent | 84.0 | Very feasible and maps cleanly to the documentation workshop, less differentiating for DevOps/Cloud |
| 5 | Backlog Hygiene Agent | 75.0 | Maps strongly to Jira governance but is less aligned with infrastructure/platform roles |

Weights: career relevance 20, hackathon similarity 15, differentiation 15, learning 10, GitHub demonstrability 10, OSS/free purity 10, security/SRE 5, agent engineering depth 5, feasibility 5, live-demo quality 5.

## Tool gate

| Component | Catalogue status/evidence used | MVP role | Decision |
|---|---|---|---|
| Ollama | DevOps Tools Catalog: MLOps/AI; OSS, needs-review; upstream MIT verified | Optional local LLM | ALLOW |
| Qwen3-4B | Model weights, Apache-2.0 verified | Default local model | ALLOW |
| Conftest | DevOps Tools Catalog: application/cloud security; needs-review; upstream Apache-2.0 verified | Required policy gate; later real-tool verification PASS | ALLOW WITH REVIEW NOTE |
| Trivy | DevOps Tools Catalog: container/Kubernetes security; upstream Apache-2.0 verified | Required configuration gate + CI | ALLOW |
| Docker Compose | DevOps Tools Catalog: OSS, active | Optional local services | ALLOW |
| Docker OpenTelemetry LGTM | DevOps Tools Catalog: OSS, active | Demo observability backend | ALLOW |
| OpenTelemetry | DevOps Tools Catalog: observability | Optional tracing | ALLOW |
| DeepEval | DevOps Tools Catalog: open-core, active | Portfolio model evaluation | PORTFOLIO ONLY |
| mcp-server-kubernetes | DevOps Tools Catalog: OSS, active | Portfolio live Kubernetes tools | PORTFOLIO ONLY |
| GitHub Actions | DevOps Tools Catalog: CI/CD | CI on GitHub | FREE-TIER DEPENDENCY |

## Evidence-based implementation status

The candidate-ranking scores above are historical project-selection judgments, not implementation or security measurements. Numeric self-ratings have been removed.

The original P0 implementation pass reproduced and fixed four boundaries: content-bound approval, operator-sourced replacement images, required fail-closed gates with host-privilege checks, and exclusive temporary-file replacement. Its 29-unit/23-security result and blocked Conftest/demo status are historical; later independent verification completed the real Conftest, Trivy, and hardened happy path successfully. See [VALIDATION.md](VALIDATION.md) for current commit-specific results and [security boundaries](docs/security.md).

Deferred portfolio ideas, outside this P0 phase and not a publish recommendation:
1. branch/PR-based remediation so the final mutation is native GitOps rather than a working-tree replacement;
2. read-only live Kubernetes/MCP inventory plus a deliberately scoped mutation tool;
3. full OpenTelemetry metrics/traces dashboard and DeepEval regressions for the Ollama advisory layer.
