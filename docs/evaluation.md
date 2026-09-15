# Evaluation

The MVP uses code-based evaluations. `make PYTHON=python3 eval` verifies:

- a healthy manifest produces no findings;
- the insecure fixture produces the expected rule set;
- a prompt-injection annotation does not alter diagnosis;
- an unpinned manifest without trusted operator replacement input retains an image finding, fails the built-in gate, and cannot become `safe_to_apply`. Missing scanners alone cannot satisfy this assertion.

These checks are fixture assertions, not broad prompt-injection or security certification. Diagnosis is deterministic; PLAN may execute installed scanners, create temporary files, and write telemetry. Run `make PYTHON=python3 test` for approval, trusted-input, gate, privilege, and filesystem regressions. The security regression suite in [test_security_regressions.py](../tests/test_security_regressions.py) uses explicit scanner mocks for authorization checks and isolated subprocess tests for Makefile argument handling. Exact executed counts and real scanner results are recorded separately in [VALIDATION.md](../VALIDATION.md).

The portfolio edition can add DeepEval, already present in DevOps Tools Catalog, for model-output quality regression tests. The authorization path should still remain code-based.
