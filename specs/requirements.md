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

## P0 boundary requirements

- WHEN candidate, canonical target, or source hash differs from the approved identity, APPLY SHALL reject after recomputing the shared canonical digest.
- WHEN serialized safety or gate results are edited, APPLY SHALL ignore them as authorization and derive safety from fresh validation.
- WHEN an unpinned image needs replacement, only explicit operator input SHALL select it; annotations and model output SHALL NOT. Ambiguous multi-container image replacement SHALL refuse.
- WHEN built-in checks, Conftest with reviewed nonempty policies, or Trivy do not report PASS, APPLY SHALL refuse, including unavailable tools, errors, and timeouts.
- WHEN a candidate enables privileged execution, hostNetwork, hostPID, hostIPC, hostPath, or added Linux capabilities, the built-in gate SHALL report HIGH/CRITICAL findings and reject it. Container checks include init and ephemeral containers.
- WHEN replacing a target in a stable operator-controlled checkout, APPLY SHALL require a regular file inside the root and use exclusive same-directory temporary creation, flush/fsync, atomic replacement, and failure cleanup.
- SCAN/PLAN SHALL preserve the source manifest; this SHALL NOT be described as globally read-only because logs, proposals, scanner caches, and temporary validation files may be written.
- Claims SHALL distinguish mocked gate tests from actual binary execution and bounded filesystem tests from resistance to concurrent hostile writers. See [validation](../VALIDATION.md).
