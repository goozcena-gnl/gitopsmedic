# Design

GitOpsMedic separates **facts and mutation** from **LLM advice**. The deterministic analyzer owns findings. The deterministic remediator owns candidate generation. Ollama is advisory only. Validation gates decide whether a proposal may enter the human-approval stage.

```mermaid
flowchart LR
  R[Git repository] --> S[Deterministic scanner]
  S --> F[Normalized findings]
  F --> L[Ollama advisory explainer]
  F --> D[Deterministic remediator]
  D --> V[Built-in + Conftest + Trivy gates]
  V -->|safe| P[Immutable proposal + diff]
  P --> H{Exact human approval token?}
  H -->|no| X[Reject]
  H -->|yes| C{Source SHA unchanged?}
  C -->|no| X
  C -->|yes| V2[Revalidate]
  V2 -->|pass| W[Atomic repository write]
  S -. telemetry .-> O[JSONL / OpenTelemetry]
  V -. telemetry .-> O
  W -. telemetry .-> O
```
