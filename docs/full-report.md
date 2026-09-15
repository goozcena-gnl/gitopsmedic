# GitOpsMedic — applied research report

Research snapshot: 2026-09-10. DevOps Tools Catalog snapshot: `62a6cd841f0db0eea9b5ef93ef6b878f50fa9db8`.

## A — Hackathon analysis

The Onepoint × AWS event is scheduled for 29 September 2026 at Cité Numérique in Bègles. Participants choose one of three workshops: Jira Governance Agent, CloudOps Agent, or Documentation Agent. The CloudOps case inventories RDS versions/tags/maintenance windows, finds version gaps, proposes remediation according to environment criticality, and applies changes only with guardrails and human validation. The published agenda contains five net development hours before pitches.

## B — Relevant engineering patterns

The reusable pattern is not "AWS-specific agent" but `observe -> normalize evidence -> reason -> propose -> authorize -> execute -> observe/evaluate`. The key design decision for a portfolio project is to keep the generative model outside the authorization boundary.

## C — Verified DevOps Tools Catalog allow-list

MVP/runtime tools: Python; Ollama (optional); Conftest and Trivy (required for the hardened APPLY profile); Docker Compose (optional); OpenTelemetry (optional); Docker OpenTelemetry LGTM (optional); GitHub Actions for public-repository CI; NGINX as the demo workload. Portfolio-only candidates: DeepEval and mcp-server-kubernetes. All tool choices were found in DevOps Tools Catalog. Qwen3-4B is an optional model artifact rather than a tooling dependency; its weights are Apache-2.0, but it is not claimed as a DevOps Tools Catalog entry.

## D — AWS/Kiro/AgentCore → OSS/local mapping

| Concern | Reference | GitOpsMedic implementation |
|---|---|---|
| Runtime | AgentCore Runtime | Python process / optional Docker |
| Model | Bedrock-compatible model access | optional Ollama local inference |
| Gateway / MCP | AgentCore Gateway | deferred to portfolio edition; approved Kubernetes MCP candidate |
| Memory | AgentCore Memory | mutable proposal JSON with content-bound identity + run log, no conversational memory in MVP |
| Identity | AgentCore Identity | local process + approval argument; token is not authentication; richer identity deferred |
| Policy | AgentCore Policy | required built-in rules, Conftest/Rego, and Trivy configuration gate |
| Guardrails | AgentCore policy/authorization | LLM output not authoritative; recomputed digest; regular target within root; SHA precondition; revalidation |
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

Input: one Kubernetes Deployment JSON file and optional explicit operator replacement image. Output: normalized findings, advisory explanation, deterministic candidate, diff, gate results, and a canonical source/target/candidate digest. APPLY recomputes that digest, checks the supplied approval and source SHA, and requires all fresh security gates to PASS. Proposal JSON and display fields are not immutable artifacts.

## I — Portfolio architecture

See `specs/design.md` and `docs/architecture.md`. The main extension is to replace working-tree apply with branch/commit/PR creation and add a read-only live Kubernetes MCP source.

## J — Security & human-in-the-loop model

SCAN and PLAN preserve the source manifest while writing telemetry and validation/proposal artifacts. Normal APPLY requires an explicit token; the demo automatically approves its temporary copied target. LLM text is never executed or used as remediation authority. All three security gates must PASS; unavailable scanners, source changes, and content/target tampering block APPLY. Exclusive temporary creation addresses the reproduced predictable-symlink attack, not concurrent hostile directory races. See [security.md](security.md).

## K — Repository structure

The project separates source, policies, tests, evaluations, examples, specs, documentation, CI and optional local services. See the repository tree and README.

## L — Implementation

Implemented in Python 3.11+ with zero mandatory Python dependencies. The optional Ollama path uses the standard-library HTTP client. External scanner invocation uses fixed argument arrays and never `shell=True`.

## M — Testing & evaluation

Implemented evaluations: healthy configuration, known-insecure configuration, metadata injection in deterministic diagnosis, and an unfixable image-version case. The P0 suite adds content/target tampering, trusted-image input, missing/failing gates, host privileges, exclusive temp replacement, and LLM non-authority checks. Executed results and mock-versus-real distinctions are in [VALIDATION.md](../VALIDATION.md).

## N — Observability

Every scan/proposal/apply stage emits local JSONL events. When the OpenTelemetry Python extra is installed and `OTEL_EXPORTER_OTLP_ENDPOINT` is set, spans are exported over OTLP. Grafana Docker OpenTelemetry LGTM is supplied as the optional local backend.

## O — CI/CD

The workflow compiles Python, runs unit tests, runs deterministic agent evaluations, and performs a Trivy config gate. It intentionally avoids a marketplace checkout action and uses only a standard public GitHub runner plus CLI/container tooling.

## P — README

`README.md` is designed for a 30–60 second recruiter scan: problem, architecture, safety boundary, quick start, optional local AI, observability, evaluation, limitations and roadmap.

## Q — Hackathon comparison

GitOpsMedic mirrors the CloudOps workshop's remediation/guardrail/human-validation pattern but changes the target from AWS RDS to declarative Kubernetes configuration. It does not claim that local components reproduce AgentCore's managed runtime, identity, gateway, memory or policy services.

## R — Evidence-based status

Numeric implementation self-ratings have been removed. Four P0 attacks were reproduced before fixes and now pass negative regressions. Local unit tests, evaluations, compilation, Trivy fixture checks, and cached Python-container tests passed. The original implementation run lacked Conftest and was blocked, but later independent real-tool verification passed Conftest, Trivy, and the complete hardened workflow. This is a bounded hardening result, not production certification; see [security.md](security.md) for unresolved assumptions and [VALIDATION.md](../VALIDATION.md) for commit-specific results. The project-selection scores in section F are historical preferences, not measured security evidence.

## S — Exact next actions

1. Independently review the canonical proposal digest, trusted image input, required gate decision, and atomic replacement helper with their regressions.
2. Run `make PYTHON=python3 test eval compile` and the security regression suite.
3. Run real Conftest and the full hardened demo with an explicitly reviewed image; record actual tool versions and results.
4. Keep PR automation, live Kubernetes/MCP, observability expansion, and richer identity outside P0. This phase performs no push or merge.
