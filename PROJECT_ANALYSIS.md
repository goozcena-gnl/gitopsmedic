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
| Ollama | Devops-Tools: MLOps/AI; OSS, needs-review; upstream MIT verified | Optional local LLM | ALLOW |
| Qwen3-4B | Model weights, Apache-2.0 verified | Default local model | ALLOW |
| Conftest | Devops-Tools: application/cloud security; needs-review; upstream Apache-2.0 verified | Optional policy gate | ALLOW WITH REVIEW NOTE |
| Trivy | Devops-Tools: container/Kubernetes security; upstream Apache-2.0 verified | Optional security gate + CI | ALLOW |
| Docker Compose | Devops-Tools: OSS, active | Optional local services | ALLOW |
| Docker OpenTelemetry LGTM | Devops-Tools: OSS, active | Demo observability backend | ALLOW |
| OpenTelemetry | Devops-Tools: observability | Optional tracing | ALLOW |
| DeepEval | Devops-Tools: open-core, active | Portfolio model evaluation | PORTFOLIO ONLY |
| mcp-server-kubernetes | Devops-Tools: OSS, active | Portfolio live Kubernetes tools | PORTFOLIO ONLY |
| GitHub Actions | Devops-Tools: CI/CD | CI on GitHub | FREE-TIER DEPENDENCY |

## Hiring-manager score

Initial MVP portfolio score: **88/100**.

- Architecture: 9/10
- Code quality: 8/10
- Infrastructure/platform relevance: 9/10
- Automation: 9/10
- Observability: 7/10
- Security: 10/10
- AI relevance: 8/10
- Documentation: 9/10
- Reproducibility: 10/10
- Originality: 9/10

Three highest-value next upgrades:
1. branch/PR-based remediation so the final mutation is native GitOps rather than a working-tree replacement;
2. read-only live Kubernetes/MCP inventory plus a deliberately scoped mutation tool;
3. full OpenTelemetry metrics/traces dashboard and DeepEval regressions for the Ollama advisory layer.
