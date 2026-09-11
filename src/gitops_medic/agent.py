from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .analyzer import analyze
from .llm import deterministic_explanation, explain_with_ollama
from .models import Finding, GateResult, Proposal
from .remediator import remediate, unified_diff
from .telemetry import Telemetry
from .validator import validate_candidate

def _bytes_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def load_json(path: Path) -> tuple[dict, str]:
    raw = path.read_bytes()
    return json.loads(raw.decode("utf-8")), _bytes_hash(raw)

def scan(path: Path, telemetry: Telemetry | None = None) -> list[Finding]:
    telemetry = telemetry or Telemetry()
    with telemetry.span("scan", target=str(path)):
        manifest, _ = load_json(path)
        findings = analyze(manifest)
        telemetry.event("scan.completed", target=str(path), findings=len(findings))
        return findings

def propose(path: Path, use_llm: bool = False, policy_dir: Path | None = None, telemetry: Telemetry | None = None) -> Proposal:
    telemetry = telemetry or Telemetry()
    with telemetry.span("propose", target=str(path), llm=use_llm):
        manifest, source_sha = load_json(path)
        findings = analyze(manifest)
        candidate = remediate(manifest)
        gates, safe = validate_candidate(candidate, policy_dir)
        explanation, llm_status = explain_with_ollama(findings, path.name) if use_llm else (deterministic_explanation(findings), "NOT_RUN")
        gates.append(GateResult("ollama-advisory", llm_status, "advisory only; never authoritative for apply"))
        diff = unified_diff(manifest, candidate, str(path))
        digest_material = (source_sha + json.dumps(candidate, sort_keys=True)).encode()
        proposal_id = hashlib.sha256(digest_material).hexdigest()[:16]
        proposal = Proposal(proposal_id, str(path), source_sha, candidate, diff, findings, explanation, gates, safe)
        telemetry.event("proposal.created", target=str(path), proposal_id=proposal_id, safe_to_apply=safe, findings=len(findings))
        return proposal

def save_proposal(proposal: Proposal, directory: Path = Path(".gitops-medic/proposals")) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{proposal.proposal_id}.json"
    path.write_text(json.dumps(proposal.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path

def apply_proposal(proposal_path: Path, approval: str, repo_root: Path | None = None, telemetry: Telemetry | None = None) -> Path:
    telemetry = telemetry or Telemetry()
    data = json.loads(proposal_path.read_text(encoding="utf-8"))
    proposal_id = data["proposal_id"]
    if approval != proposal_id:
        telemetry.event("apply.rejected", proposal_id=proposal_id, reason="approval-token-mismatch")
        raise PermissionError("Exact proposal id is required as the approval token.")
    if data.get("safe_to_apply") is not True:
        telemetry.event("apply.rejected", proposal_id=proposal_id, reason="proposal-not-safe")
        raise PermissionError("Proposal is not marked safe_to_apply.")
    root = (repo_root or Path.cwd()).resolve()
    target = Path(data["target"])
    if not target.is_absolute():
        target = (root / target).resolve()
    else:
        target = target.resolve()
    if not target.is_relative_to(root):
        telemetry.event("apply.rejected", proposal_id=proposal_id, reason="target-outside-repo")
        raise PermissionError("Target must remain inside the repository root.")
    current = target.read_bytes()
    if _bytes_hash(current) != data["source_sha256"]:
        telemetry.event("apply.rejected", proposal_id=proposal_id, reason="source-changed")
        raise RuntimeError("Target changed after proposal creation; create a new proposal.")
    candidate = data["candidate"]
    final_gates, safe = validate_candidate(candidate, root / "policies")
    if not safe:
        telemetry.event("apply.rejected", proposal_id=proposal_id, reason="revalidation-failed")
        raise PermissionError("Candidate failed apply-time revalidation.")
    tmp = target.with_suffix(target.suffix + ".gitops-medic.tmp")
    tmp.write_text(json.dumps(candidate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(target)
    telemetry.event("apply.completed", proposal_id=proposal_id, target=str(target), gates=[g.status for g in final_gates])
    return target
