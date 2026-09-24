# Research snapshot — 2026-09-10

## Onepoint × AWS hackathon
Official page: https://www.groupeonepoint.com/fr/actualites/hackathon-ia-aws-x-onepoint/

The event is on 29 September 2026 at Onepoint's Bordeaux HQ, Cité Numérique, Bègles. The three workshops are Jira Governance Agent, CloudOps Agent, and Documentation Agent. The CloudOps workshop analyzes AWS RDS versions, tags and maintenance windows, proposes remediation, and applies changes with guardrails and human validation. The published schedule gives two development blocks: 10:30–13:00 and 14:00–16:30.

## AWS architectural reference
- AgentCore overview: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/what-is-bedrock-agentcore.html
- Gateway: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway.html
- Observability: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability.html
- Evaluations: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/evaluations.html
- Pricing: https://aws.amazon.com/bedrock/agentcore/pricing/

AWS is not a runtime dependency here because AgentCore is consumption-priced; new-account credits are temporary.

## Kiro architectural reference
Feature Specs use Requirements -> Design -> Tasks and support requirements-first/design-first workflows: https://kiro.dev/docs/specs/feature-specs/

The repository keeps equivalent artifacts under `specs/` but does not require Kiro.

## DevOps Tools Catalog allow-list snapshot
Evidence was checked against `goozcena-gnl/devops-tools-catalog` main commit `62a6cd841f0db0eea9b5ef93ef6b878f50fa9db8` (2026-09-10). Relevant catalogue entries include Ollama, DeepEval, Conftest, Trivy, Docker Compose, Docker OpenTelemetry LGTM, GitHub Actions, mcp-server-kubernetes, and OpenTelemetry.

## Conftest compatibility note
Conftest v0.68.x uses Rego v1 by default. The included policy therefore uses current `deny contains msg if { ... }` syntax, matching the official Conftest example checked on 2026-09-10.


## Version pins used in the optional demo path
- Ollama container: `ollama/ollama:0.33.3` (stable tag verified on Docker Hub on 2026-09-10; 0.34.0 was released the same day and was intentionally not adopted immediately).
- Grafana OTel LGTM: `grafana/otel-lgtm:0.32.1` (current stable tag checked on 2026-09-10).
- Trivy CI container: `aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969` (tag `0.74.0`, registry digest verified on 2026-09-21).
