# Security model

| Threat | Prevention | Detection | Recovery |
|---|---|---|---|
| Prompt injection in repository | Never feed raw repo instructions as authoritative; LLM sees normalized findings only | Prompt-injection eval fixture | Fall back to deterministic explanation |
| Arbitrary command execution | No shell execution from model output; subprocess uses fixed argv for approved scanners | Code review/tests | Disable optional scanners |
| Excessive mutation | Plan is read-only; exact approval required | `apply.rejected` / `apply.completed` telemetry | Revert Git commit |
| Stale proposal / TOCTOU | SHA-256 precondition | Apply rejects changed source | Regenerate proposal |
| Hallucinated remediation | Remediation is deterministic, not authored by LLM | Built-in policy validation | Reject unsafe proposal |
| Malicious tool output | Scanner output is not executable | Gate status + logs | Mark gate failed |
| Supply-chain risk | Minimal Python dependencies; Trivy gate; pin external tools in production | CI | Upgrade/pin after review |
| Secret leakage | No cloud credentials required; local-first default | Trivy secret scanning can be added | Rotate exposed credentials |
