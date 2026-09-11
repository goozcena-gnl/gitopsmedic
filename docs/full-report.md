# GitOpsMedic — applied research report

Research snapshot: 2026-09-10. Devops-Tools snapshot: `62a6cd841f0db0eea9b5ef93ef6b878f50fa9db8`.

## A — Hackathon analysis

The Onepoint × AWS event is scheduled for 29 September 2026 at Cité Numérique in Bègles. Participants choose one of three workshops: Jira Governance Agent, CloudOps Agent, or Documentation Agent. The CloudOps case inventories RDS versions/tags/maintenance windows, finds version gaps, proposes remediation according to environment criticality, and applies changes only with guardrails and human validation. The published agenda contains five net development hours before pitches.

## B — Relevant engineering patterns

The reusable pattern is not "AWS-specific agent" but `observe -> normalize evidence -> reason -> propose -> authorize -> execute -> observe/evaluate`. The key design decision for a portfolio project is to keep the generative model outside the authorization boundary.

## C — Verified Devops-Tools allow-list

MVP/runtime tools: Python; Ollama (optional); Conftest (optional); Trivy (optional); Docker Compose (optional); OpenTelemetry (optional); Docker OpenTelemetry LGTM (optional); GitHub Actions for public-repository CI; NGINX as the demo workload. Portfolio-only candidates: DeepEval and mcp-server-kubernetes. All tool choices were found in Devops-Tools. Qwen3-4B is an optional model artifact rather than a tooling dependency; its weights are Apache-2.0, but it is not claimed as a Devops-Tools catalogue entry.

## D — AWS/Kiro/AgentCore → OSS/local mapping

| Concern | Reference | GitOpsMedic implementation |
|---|---|---|
| Runtime | AgentCore Runtime | Python process / optional Docker |
| Model | Bedrock-compatible model access | optional Ollama local inference |
| Gateway / MCP | AgentCore Gateway | deferred to portfolio edition; approved Kubernetes MCP candidate |
| Memory | AgentCore Memory | immutable proposal data + run log, no conversational memory in MVP |
| Identity | AgentCore Identity | local process + explicit human authorization; richer identity deferred |
| Policy | AgentCore Policy | deterministic built-in rules + optional Conftest/Rego |
| Guardrails | AgentCore policy/authorization | no LLM writes; exact approval token; target boundary; SHA precondition; revalidation |
| Observability | AgentCore Observability | JSONL events + optional OpenTelemetry -> Grafana LGTM |
| Evaluation | AgentCore Evaluations | deterministic scenario suite; DeepEval later for model-output quality |
| Spec workflow | Kiro Feature Specs | committed `requirements.md`, `design.md`, `tasks.md` |

This is a mapping of engineering concerns, not feature equivalence.

## E — Five project candidates

1. GitOpsMedic — repository-level CloudOps remediation agent for Kubernetes/IaC/GitOps.
2. KubeUpgrade Agent — version/EOL and upgrade planning agent for Kubernetes platform components.
3. SRE Triage Agent — correlates local telemetry to produce evidence-grounded incident hypotheses.
4. DocDrift Agent — detects infrastructure/code/documentation drift and proposes documentation patches.
5. Backlog Hygiene Agent — local issue/backlog governance inspired by the Jira workshop.

## F — Weighted scoring

| Rank | Candidate | Score /100 |
|---:|---|---:|
| 1 | GitOpsMedic | 94.0 |
| 2 | KubeUpgrade Agent | 90.5 |
| 3 | SRE Triage Agent | 88.5 |
| 4 | DocDrift Agent | 84.0 |
| 5 | Backlog Hygiene Agent | 75.0 |

Weights: career 20, hackathon fit 15, differentiation 15, learning 10, GitHub demo 10, OSS/free 10, security/SRE 5, agent depth 5, feasibility 5, live demo 5.

## G — Selected project

**GitOpsMedic** wins because it demonstrates CloudOps, Kubernetes, GitOps, policy-as-code, security, human-in-the-loop automation, evaluation and observability in a repository a recruiter can run without an AWS account.

## H — MVP specification

Input: one Kubernetes Deployment JSON file. Output: normalized findings, advisory explanation, deterministic candidate, diff, gate results and an immutable proposal ID. Mutation is a separate command that requires exact human approval and a matching source SHA.

## I — Portfolio architecture

See `specs/design.md` and `docs/architecture.md`. The main extension is to replace working-tree apply with branch/commit/PR creation and add a read-only live Kubernetes MCP source.

## J — Security & human-in-the-loop model

READ and PLAN are automatic. APPLY is privileged and explicit. Raw repository instructions and raw LLM text are never executed. A candidate must pass deterministic rules; optional Conftest/Trivy failures are blocking; stale proposals fail closed.

## K — Repository structure

The project separates source, policies, tests, evaluations, examples, specs, documentation, CI and optional local services. See the repository tree and README.

## L — Implementation

Implemented in Python 3.11+ with zero mandatory Python dependencies. The optional Ollama path uses the standard-library HTTP client. External scanner invocation uses fixed argument arrays and never `shell=True`.

## M — Testing & evaluation

Implemented scenarios: healthy configuration, known-insecure configuration, prompt injection embedded in repository metadata, and an unfixable image-version case. Unit tests additionally cover wrong approval, successful approval, and stale-source rejection.

## N — Observability

Every scan/proposal/apply stage emits local JSONL events. When the OpenTelemetry Python extra is installed and `OTEL_EXPORTER_OTLP_ENDPOINT` is set, spans are exported over OTLP. Grafana Docker OpenTelemetry LGTM is supplied as the optional local backend.

## O — CI/CD

The workflow compiles Python, runs unit tests, runs deterministic agent evaluations, and performs a Trivy config gate. It intentionally avoids a marketplace checkout action and uses only a standard public GitHub runner plus CLI/container tooling.

## P — README

`README.md` is designed for a 30–60 second recruiter scan: problem, architecture, safety boundary, quick start, optional local AI, observability, evaluation, limitations and roadmap.

## Q — Hackathon comparison

GitOpsMedic mirrors the CloudOps workshop's remediation/guardrail/human-validation pattern but changes the target from AWS RDS to declarative Kubernetes configuration. It does not claim that local components reproduce AgentCore's managed runtime, identity, gateway, memory or policy services.

## R — Portfolio score

Initial score: **88/100**. Strongest signals are safety architecture, reproducibility, CloudOps/GitOps relevance and testing. Current weaknesses are MVP-only JSON input, no PR creation yet, no live Kubernetes/MCP integration, and optional observability/scanner paths not exercised in the build sandbox.

## S — Exact next actions

1. Create a public `gitops-medic` GitHub repository and push this artifact.
2. Run `make test`, `make eval`, `make demo` on the development machine.
3. Install/run Conftest and Trivy and capture a verified gate transcript.
4. Enable optional Ollama with a reviewed local model and record a 60–90 second demo.
5. Add branch/PR-based remediation before adding live Kubernetes mutation.
6. Add OpenTelemetry/Grafana screenshots and a small dashboard.
7. Only then add a read-only Kubernetes MCP integration and scoped write capability.
