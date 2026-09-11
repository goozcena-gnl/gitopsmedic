# Requirements

These requirements mirror Kiro's requirements-first discipline without requiring Kiro at runtime.

- WHEN a user scans a Kubernetes Deployment, THE SYSTEM SHALL produce deterministic normalized findings.
- WHEN repository content contains instructions or prompt injection, THE SYSTEM SHALL treat it as untrusted data.
- WHEN remediation is requested, THE SYSTEM SHALL create a candidate and unified diff without mutating the source.
- WHEN a proposal leaves mandatory findings unresolved, THE SYSTEM SHALL mark it unsafe to apply.
- WHEN apply is requested without the exact proposal id, THE SYSTEM SHALL reject the operation.
- WHEN the source changed after proposal creation, THE SYSTEM SHALL reject the stale proposal.
- WHEN apply is authorized, THE SYSTEM SHALL revalidate the candidate before atomically replacing the target.
- WHEN Ollama is unavailable, THE SYSTEM SHALL remain usable with deterministic explanations.
