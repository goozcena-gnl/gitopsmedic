# Tasks

## MVP — complete in this artifact
- [x] deterministic Kubernetes Deployment scanner
- [x] deterministic remediation plan and diff
- [x] human approval token
- [x] source hash precondition
- [x] built-in validation gate
- [x] required fail-closed Conftest and Trivy gates (real Conftest execution remains NOT RUN locally)
- [x] optional Ollama advisory explanation
- [x] JSONL telemetry + optional OTLP tracing
- [x] evaluation scenarios and unit tests
- [x] GitHub Actions workflow

## P0 hardening
- [x] reproduce SEC-001 through SEC-004 with failing outcome-based regressions
- [x] bind approval to canonical source/target/candidate content and revalidate at APPLY
- [x] replace annotation authority with explicit operator image input
- [x] require all security gates and detect high-impact host privileges
- [x] replace predictable temp writes with exclusive atomic replacement
- [x] reconcile guarantees with executed tests and documented limitations
- [ ] independently run real Conftest and a full hardened happy-path demo

## Portfolio edition
- [ ] YAML support without introducing an unverified dependency
- [ ] live read-only Kubernetes inventory via approved MCP server
- [ ] Git branch/PR writer instead of direct file replacement
- [ ] persistent evaluation dashboard
- [ ] OpenTelemetry metrics in addition to traces/logs
- [ ] identity and scoped tool permissions
- [ ] add Terraform/OpenTofu rules
