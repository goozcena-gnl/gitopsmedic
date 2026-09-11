# Onepoint / AWS mapping

| Hackathon / AgentCore concern | GitOpsMedic |
|---|---|
| CloudOps inventory | Declarative Kubernetes manifest scan |
| Runtime | Local Python process / optional Docker |
| Model | Ollama + local Qwen3-4B, advisory only |
| Gateway / MCP | Deferred; portfolio extension with an approved MCP server |
| Memory | Proposal JSON + run telemetry; no conversational memory in MVP |
| Identity | Content-bound approval + local process identity; token is not authentication; full identity layer deferred |
| Policy | Required built-in rules, Conftest/Rego, and Trivy configuration gate |
| Guardrails | LLM output excluded from candidate/authorization; recomputed source/target/candidate digest; SHA precondition; revalidation |
| Observability | JSONL events + optional OpenTelemetry to Grafana LGTM |
| Evaluations | Deterministic scenarios; DeepEval is a later model-quality extension |
| Deployment | Local-first; no AWS account required |

This is a mapping of engineering concerns, not a claim of feature equivalence with managed AWS services.
