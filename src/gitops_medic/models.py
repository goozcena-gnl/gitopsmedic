from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    message: str
    path: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class GateResult:
    name: str
    status: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class Proposal:
    proposal_id: str
    target: str
    source_sha256: str
    candidate: dict[str, Any]
    diff: str
    findings: list[Finding]
    explanation: str
    gates: list[GateResult] = field(default_factory=list)
    safe_to_apply: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "target": self.target,
            "source_sha256": self.source_sha256,
            "candidate": self.candidate,
            "diff": self.diff,
            "findings": [f.to_dict() for f in self.findings],
            "explanation": self.explanation,
            "gates": [g.to_dict() for g in self.gates],
            "safe_to_apply": self.safe_to_apply,
        }
