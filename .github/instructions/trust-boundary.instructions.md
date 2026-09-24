---
applyTo: "AGENTS.md,.github/**,policies/**,src/**,specs/**,scripts/**,tests/**"
---

# Trust-Boundary Instructions

- Treat changes to agent instructions, policies, approval handling, proposal identity, scanner provenance, apply logic, and validation gates as security-sensitive.
- Never let an agent weaken a rule and then use that weakened rule as evidence that its own change is safe.
- Preserve exact approval-token binding, source SHA-256 freshness checks, deterministic candidate generation, and mandatory apply-time revalidation.
- LLM output must remain advisory and must never become executable shell, authorization input, or direct mutation logic.
- Required Conftest and Trivy gates must fail closed when unavailable or untrusted.
- Add regression coverage for any change to authorization, provenance, path handling, OCI identity, or APPLY behavior.
