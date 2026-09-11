# Security model

## P0 hardening evidence

The 2026-09-11 pass reproduced each technical finding before changing its implementation. Tests are in [test_security_regressions.py](../tests/test_security_regressions.py). Results below describe tested boundaries, not a general security certification.

| Finding | Previous behavior | Hardened behavior | Regression test |
|---|---|---|---|
| SEC-001 | Stored proposal ID and safety flag trusted | APPLY recomputes the canonical digest and derives safety from fresh gates | `test_candidate_substitution_rejected`, `test_target_substitution_rejected`, `test_serialized_safety_is_audit_only` |
| SEC-002 | Manifest annotation chose replacement image | Only explicit operator input chooses an image replacement | `test_manifest_annotation_cannot_choose_replacement`, `test_trusted_image_is_deterministic_visible_and_llm_independent` |
| SEC-003 | Missing scanners did not block; host privileges were missed | All three gates must PASS; bounded host-privilege checks are mandatory | `test_required_scanner_unavailable_refuses_apply`, `test_dangerous_pod_privileges_refuse_apply`, `test_dangerous_container_privileges_refuse_apply` |
| SEC-004 | Predictable temp path followed a symlink | Exclusive same-directory temp creation and atomic replacement | `test_predictable_temp_symlink_never_writes_outside`, `test_atomic_failure_cleans_temp_and_preserves_target` |

Before fixes: SEC-001 failed 3 regressions, SEC-002 failed its image assertion, SEC-003 failed 14 subcases, and SEC-004 overwrote an outside file in the test sandbox. After fixes: all those regressions pass. See [VALIDATION.md](../VALIDATION.md) for actual tool availability and commands.

## Approval identity

One `proposal_digest` function computes full SHA-256 over a JSON object containing the source byte hash, resolved absolute target path, and candidate. Serialization uses sorted keys, compact separators, UTF-8, `ensure_ascii=False`, and rejects non-finite numbers. PLAN stores the absolute target and digest; APPLY requires stored ID = recomputed ID = operator approval. Moving a proposal to a different checkout requires a new PLAN.

APPLY ignores serialized `safe_to_apply` and recorded gate results for authorization. It rechecks source bytes and reruns validation. Changes to the candidate, target, or source hash invalidate the original token. JSON key order and whitespace do not alter candidate identity.

This is content binding, not signing or authentication. Anyone with the ability to supply an approval can approve a new digest. Operators must review the actual candidate and target produced by a trusted local PLAN invocation. Stored explanation, diff, findings, and prior gate results are mutable display/audit fields, not integrity-protected review evidence. Old 16-character proposal tokens are incompatible; regenerate proposals.

## Trusted remediation inputs

Use `propose --replacement-image <reviewed-image>` for an unpinned image. The `gitops-medic.dev/safe-image` annotation is retained as inert input metadata, never read as remediation authority. Without operator input the unpinned image remains unresolved and blocks APPLY. The replacement is visible in the generated diff and bound by the candidate digest.

Explicit image replacement accepts only one regular container and no init/ephemeral containers. Ambiguous workloads refuse replacement; review them manually. Already versioned images are not automatically replaced. The tool does not attest registry provenance, image signatures, tag immutability, or workload compatibility. Existing deterministic resource/security defaults remain opinionated demo changes that require review.

## Execution profile

There is one hardened profile, with no development bypass. PLAN and APPLY require explicit PASS from:

1. Built-in deterministic analysis, including privileged containers, hostNetwork, hostPID, hostIPC, hostPath, and nonempty capabilities.add. Container checks include regular, init, and ephemeral containers. These privileges are findings, not automatically removed.
2. Conftest using a nonempty reviewed Rego policy directory. This repository ships policies, so policy validation is always configured; absent/empty policies are not a disable switch. API PLAN can take a policy directory; CLI PLAN uses `./policies`, and APPLY always uses `<repo_root>/policies`.
3. Trivy configuration analysis at HIGH/CRITICAL severity.

Missing tools or policies produce `NOT RUN` and `safe_to_apply=False`. Scanner errors, timeouts, and nonzero exits produce FAIL. APPLY reports the blocking gate names/statuses and next steps without including raw scanner output. A scanner exit code of zero is trusted under the assumption that the executable, configuration, and policies are operator-reviewed. `trivy config` is not a container-image vulnerability or secret scan.

Ollama is advisory, never a required security gate. Unit tests mock external gate results to test authorization independently of installations; those mocks do not prove real scanner compatibility. Real Conftest execution was NOT RUN locally because its binary is absent.

## Filesystem boundary

For a stable local repository owned by the operator, APPLY rejects targets outside the resolved repository root and targets that fail `lstat` regular-file checks. It creates a new file with `mkstemp` inside the target directory, writes through that descriptor, flushes/fsyncs, rechecks the source, atomically replaces the target, and fsyncs the parent directory. Tests show that the old predictable symlink cannot redirect a write, the target remains regular, and temporary files are cleaned after injected pre-replacement failures. Ordinary permission bits are preserved; ownership, ACLs, extended attributes, and special mode bits are not preserved as a contract.

This is not protection against a concurrent hostile process renaming directories or racing the final source check and replacement. Use an operator-controlled checkout without concurrent writers. An fsync error after replacement can report failure even though the candidate was installed; inspect the target before retrying. A crash may leave a temporary file; crash/power-loss recovery was not tested.

SCAN/PLAN leave the source manifest unchanged, but are not globally read-only: telemetry writes JSONL, CLI PLAN saves proposals, validators create temporary files, and scanners may update caches. Demo automatically supplies its token only for a temporary copied target; it is not evidence of a human approval action. Proposal/log output directories and environment-selected paths must be operator-controlled. Their symlink behavior is outside this target-replacement fix; do not run with elevated privileges in an attacker-writable checkout.

## LLM boundary and remaining risks

Candidate generation precedes advisory inference. Model text is stored/displayed, never parsed into candidate fields, targets, digests, approval values, or subprocess argv. A mocked malicious explanation leaves candidate, target, and digest unchanged in regression tests. The metadata-injection evaluation proves deterministic diagnosis only, not model-level prompt-injection resistance. Findings and file names may contain untrusted strings; a prompt is not a security boundary, and advisory text can mislead a reviewer.

P1: independent real Conftest/full-profile replay; trusted policy/scanner provenance; concurrent filesystem races and auxiliary output-path symlinks; operator review of unbound display fields and image provenance.

P2: complete Kubernetes schema/Pod Security Standards coverage, malformed-input diagnostics, crash recovery, file metadata preservation, and actual model-output quality evaluation. No live cluster, PR automation, MCP, multi-agent behavior, signing, or new runtime dependency was added in P0.
