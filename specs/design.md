# Design

GitOpsMedic separates **facts and mutation** from **LLM advice**. The deterministic analyzer owns findings. The deterministic remediator owns candidate generation. Ollama is advisory only. Validation gates decide whether a proposal may enter the human-approval stage.

PLAN consumes repository data and optional trusted operator image input, generates the candidate/diff, runs all three required gates, and computes one canonical source/target/candidate digest. Proposal JSON is mutable, not an immutable or signed artifact.

APPLY checks the stored, recomputed, and approved digests for equality, rejects stale sources and nonregular/outside targets, reruns built-in/Conftest/Trivy gates, and replaces through an exclusive same-directory temporary file. Recorded safety and LLM output do not authorize APPLY. No development gate override exists.

See [architecture](../docs/architecture.md) for the control flow and [security](../docs/security.md) for the tested scope, mutable display fields, auxiliary writes, and concurrent-filesystem limitations.
