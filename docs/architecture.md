# Architecture

## Principle

`READ -> PLAN -> VALIDATE -> HUMAN APPROVAL -> APPLY`

Deterministic code generates the candidate before asking the LLM for an explanation. Model text is advisory display data: it is not parsed into candidate fields or subprocess arguments. The model can emit misleading text or commands, but the application has no execution path for that text.

## Trust boundaries

1. Repository content: untrusted.
2. Scanner executables, runtime configuration, and policy rules: operator-reviewed dependencies; deterministic execution alone does not make them trustworthy.
3. LLM explanation: advisory/untrusted.
4. Replacement image: explicit operator PLAN input; annotations and the LLM cannot select it. One regular container only when replacing images.
5. Proposal identity: one canonical SHA-256 binds source bytes, resolved absolute target, and candidate. Serialized safety and display fields do not authorize writes.
6. APPLY: stored digest, independently recomputed digest, and supplied approval must match; source must remain unchanged; target must be regular and inside the root.
7. Gates: built-in analysis, Conftest with reviewed policies, and Trivy must all PASS again at APPLY. Missing gates block; there is no bypass profile.
8. Target replacement: exclusive same-directory temp file, flush/fsync, source recheck, atomic replacement, parent fsync, and cleanup on pre-replacement failure.

SCAN and PLAN preserve the source manifest, not every filesystem path: logs, saved proposals, temporary candidates, and scanner caches may be written. The demo automatically approves only its temporary copied target. Repository directories, tool configuration, and auxiliary output locations must be operator-controlled; concurrent hostile filesystem mutation is not covered. See [security.md](security.md) for the tested boundaries and limitations, and [VALIDATION.md](../VALIDATION.md) for results.
