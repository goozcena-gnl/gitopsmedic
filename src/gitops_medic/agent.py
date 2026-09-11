from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path

from .analyzer import analyze
from .llm import deterministic_explanation, explain_with_ollama
from .models import Finding, GateResult, Proposal
from .remediator import remediate, unified_diff
from .telemetry import Telemetry
from .validator import validate_candidate

def _bytes_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def proposal_digest(source_sha256: str, target: Path, candidate: dict) -> str:
    material = {"source_sha256": source_sha256, "target": str(target.resolve()), "candidate": candidate}
    return _bytes_hash(json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8"))

def _regular_target(target: Path) -> os.stat_result:
    info = target.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise PermissionError("Target must be a regular file, not a symlink or special file. Review the target and generate a new proposal.")
    return info

def _atomic_replace(target: Path, candidate: dict, source_sha256: str) -> None:
    original = _regular_target(target)
    directory_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
    temporary = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=".gitops-medic-", suffix=".tmp", dir=target.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), stat.S_IMODE(original.st_mode) & 0o777)
            stream.write(json.dumps(candidate, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        current = _regular_target(target)
        if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino) or _bytes_hash(target.read_bytes()) != source_sha256:
            raise RuntimeError("Target changed during validation; generate and review a new proposal.")
        os.replace(temporary, target)
        os.fsync(directory_fd)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        os.close(directory_fd)

def load_json(path: Path) -> tuple[dict, str]:
    raw = path.read_bytes()
    return json.loads(raw.decode("utf-8")), _bytes_hash(raw)

def scan(path: Path, telemetry: Telemetry | None = None) -> list[Finding]:
    telemetry = telemetry or Telemetry()
    telemetry.ensure_output_separate_from(path)
    with telemetry.span("scan", target=str(path)):
        manifest, _ = load_json(path)
        findings = analyze(manifest)
        telemetry.event("scan.completed", target=str(path), findings=len(findings))
        return findings

def propose(path: Path, use_llm: bool = False, policy_dir: Path | None = None, telemetry: Telemetry | None = None, *, replacement_image: str | None = None) -> Proposal:
    telemetry = telemetry or Telemetry()
    telemetry.ensure_output_separate_from(path)
    with telemetry.span("propose", target=str(path), llm=use_llm):
        _regular_target(path)
        manifest, source_sha = load_json(path)
        findings = analyze(manifest)
        candidate = remediate(manifest, replacement_image=replacement_image)
        gates, safe = validate_candidate(candidate, policy_dir)
        explanation, llm_status = explain_with_ollama(findings, path.name) if use_llm else (deterministic_explanation(findings), "NOT RUN")
        gates.append(GateResult("ollama-advisory", llm_status, "advisory only; never authoritative for apply"))
        diff = unified_diff(manifest, candidate, str(path))
        proposal_id = proposal_digest(source_sha, path, candidate)
        proposal = Proposal(proposal_id, str(path.resolve()), source_sha, candidate, diff, findings, explanation, gates, safe)
        telemetry.event("proposal.created", target=str(path), proposal_id=proposal_id, safe_to_apply=safe, findings=len(findings))
        return proposal

def _ensure_proposal_output_separate(path: Path, target: Path) -> None:
    try:
        aliases_target = path.resolve() == target.resolve()
        if not aliases_target and path.exists() and target.exists():
            aliases_target = path.samefile(target)
    except (OSError, RuntimeError) as error:
        raise PermissionError("Unable to verify that proposal output is separate from the source manifest.") from error
    if aliases_target:
        raise PermissionError("Proposal output must not alias the source manifest. Choose another proposal directory.")

def save_proposal(proposal: Proposal, directory: Path = Path(".gitops-medic/proposals")) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{proposal.proposal_id}.json"
    _ensure_proposal_output_separate(path, Path(proposal.target))
    temporary = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=".gitops-medic-proposal-", suffix=".tmp", dir=directory)
        temporary = Path(name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(proposal.to_dict(), indent=2, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return path

def apply_proposal(proposal_path: Path, approval: str, repo_root: Path | None = None, telemetry: Telemetry | None = None) -> Path:
    telemetry = telemetry or Telemetry()
    data = json.loads(proposal_path.read_text(encoding="utf-8"))
    proposal_id = data["proposal_id"]
    root = (repo_root or Path.cwd()).resolve()
    target = Path(data["target"])
    if not target.is_absolute():
        target = root / target
    resolved_target = target.resolve()
    telemetry.ensure_output_separate_from(resolved_target)
    if approval != proposal_id:
        telemetry.event("apply.rejected", proposal_id=proposal_id, reason="approval-token-mismatch")
        raise PermissionError("Exact proposal id is required as the approval token.")
    _regular_target(target)
    target = resolved_target
    if not target.is_relative_to(root):
        telemetry.event("apply.rejected", proposal_id=proposal_id, reason="target-outside-repo")
        raise PermissionError("Target must remain inside the repository root.")
    if proposal_id != proposal_digest(data["source_sha256"], target, data["candidate"]):
        telemetry.event("apply.rejected", proposal_id=proposal_id, reason="proposal-integrity-failed")
        raise PermissionError("Proposal integrity verification failed. Generate and review a new proposal before approving it.")
    current = target.read_bytes()
    if _bytes_hash(current) != data["source_sha256"]:
        telemetry.event("apply.rejected", proposal_id=proposal_id, reason="source-changed")
        raise RuntimeError("Target changed after proposal creation; create a new proposal.")
    candidate = data["candidate"]
    final_gates, safe = validate_candidate(candidate, root / "policies")
    if not safe:
        telemetry.event("apply.rejected", proposal_id=proposal_id, reason="revalidation-failed")
        blocked = ", ".join(f"{gate.name}={gate.status}" for gate in final_gates if gate.status != "PASS")
        raise PermissionError(f"Required apply-time gates did not PASS: {blocked}. Restore required tools/policies or address findings, then generate and review a new proposal.")
    _atomic_replace(target, candidate, data["source_sha256"])
    telemetry.event("apply.completed", proposal_id=proposal_id, target=str(target), gates=[g.status for g in final_gates])
    return target
