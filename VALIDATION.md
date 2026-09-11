# Validation status — 2026-09-10

| Check | Status | Evidence |
|---|---|---|
| Python compileall | PASS | Executed in build environment |
| Unit tests | PASS | 6/6 tests passed |
| Deterministic evaluations | PASS | 4/4 scenarios, 100% |
| End-to-end demo | PASS | proposal -> exact approval -> revalidation -> apply -> zero residual built-in findings |
| Editable install | PASS | `pip install --no-build-isolation -e .` + CLI help |
| Conftest runtime gate | NOT RUN | Conftest binary not installed in build environment |
| Trivy runtime gate | NOT RUN | Trivy binary not installed in build environment |
| Ollama advisory inference | NOT RUN | Ollama not installed/running in build environment |
| Docker/Grafana LGTM | NOT RUN | Docker not available in build environment |
| GitHub Actions CI | NOT RUN | repository has not yet been published |

`NOT RUN` is intentional and is not represented as a successful validation.
