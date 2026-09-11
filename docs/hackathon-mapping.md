# Onepoint / AWS mapping

| Hackathon / AgentCore concern | GitOpsMedic |
|---|---|
| CloudOps inventory | Declarative Kubernetes manifest scan |
| Runtime | Local Python process / optional Docker |
| Model | Ollama + local Qwen3-4B, advisory only |
| Gateway / MCP | Deferred; portfolio extension with an approved MCP server |
| Memory | Proposal JSON + run telemetry; no conversational memory in MVP |
| Identity | Human approval token + local process identity; full identity layer deferred |
| Policy | Built-in deterministic rules + optional Conftest/Rego |
| Guardrails | LLM cannot write; exact approval; SHA precondition; revalidation |
| Observability | JSONL events + optional OpenTelemetry to Grafana LGTM |
| Evaluations | Deterministic scenarios; DeepEval is a later model-quality extension |
| Deployment | Local-first; no AWS account required |

This is a mapping of engineering concerns, not a claim of feature equivalence with managed AWS services.
