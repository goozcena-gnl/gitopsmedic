# Validation status — 2026-09-11

| Check | Status | Evidence |
|---|---|---|
| Baseline default `make test eval compile` | BLOCKED | `python` unavailable; rerun with `PYTHON=python3` |
| Baseline unit tests / evaluations / compilation | PASS | Before edits: 6/6 tests, 4/4 evaluations, Python 3.12.3 compileall |
| Hardened Python compileall | PASS | `make PYTHON=python3 compile` |
| Hardened unit tests | PASS | `make PYTHON=python3 test`: 29 tests; external scanner outcomes explicitly mocked in approval/security tests |
| Security regressions | PASS | `PYTHONPATH=src python3 -m unittest discover -s tests -p test_security_regressions.py -v`: 23 tests, including parameterized attacks |
| Deterministic evaluations | PASS | `make PYTHON=python3 eval`: 4/4; unfixable case now requires an actual residual image finding and built-in FAIL |
| Happy-path APPLY | PASS | Unit/integration tests with explicit operator image and mocked PASS gates |
| Real hardened demo | BLOCKED | `make PYTHON=python3 demo REPLACEMENT_IMAGE=nginx:1.27.5`: built-in PASS, Trivy PASS, Conftest NOT RUN; exits 2 without APPLY |
| Conftest runtime gate | NOT RUN | Binary unavailable; no real full-profile success claimed |
| Trivy secure fixture | PASS | Installed Trivy 0.62.1: `trivy config --exit-code 1 --severity HIGH,CRITICAL examples/secure` found zero HIGH/CRITICAL findings |
| Trivy insecure-fixture detection | PASS | Real scan reported three HIGH failures (KSV014 and KSV118); this is an expected negative fixture |
| Python container unit tests | PASS | Cached `python:3.12.13-alpine3.22`, 29 tests; read-only repository mount, network disabled, writable temporary filesystem |
| Ollama advisory inference | NOT RUN | Ollama 0.32.14 reachable but no installed models; no downloads or inference performed |
| Docker availability | PASS | Docker daemon 29.1.3 reachable; used for isolated Python tests |
| Grafana / OTel services | NOT RUN | Unrelated to P0; not started |
| Editable install | NOT RUN | Not repeated in this pass; no packaging changes |
| GitHub Actions / pinned CI Trivy container | NOT RUN | No push or remote CI run; local Trivy version differs from CI's 0.74.0 pin |

`NOT RUN` is intentional and is not represented as a successful validation.

## Baseline and reproduction

Started from clean `main` at `e9751e24e1f0978cbfd346ede5d8bba969e75ec3`; work is local on `hardening/p0-security-boundaries`. SEC-001: 3 failing tampering regressions; SEC-002: attacker image selected; SEC-003: 14 failing missing-gate/privilege subcases; SEC-004: outside file overwritten via predictable symlink. Each was run before its implementation fix, then rerun with the full unit/evaluation suites before committing.

## Original attack replay

| Attack | Check result | Observed outcome |
|---|---|---|
| A: candidate changed, original token | PASS | REJECTED; target unchanged |
| B: target/source hash changed, original token | PASS | REJECTED; both targets unchanged |
| C: attacker safe-image annotation | PASS | Cannot select replacement; unpinned image remains blocked |
| D: privileged + hostPath, scanners absent | PASS | REJECTED; built-in FAIL |
| E: required scanner missing | PASS | REJECTED; serialized prior PASS cannot authorize |
| F: predictable temp symlink | PASS | Outside file unchanged; APPLY uses a new exclusive temporary file |
| G: approved original candidate | PASS | Applied with mocked PASS gates; real full-profile execution remains BLOCKED |
| H: stale source | PASS | REJECTED, including source change during validation |
| I: wrong approval | PASS | REJECTED |

Publish decision: GO WITH CONDITIONS for this bounded P0 change set, not production certification. Independently run real Conftest and the full hardened happy path, and review the trust assumptions in [docs/security.md](docs/security.md). No push or merge was performed.
