from __future__ import annotations

import hashlib
import json
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

from .analyzer import analyze
from .models import GateResult


REVIEWED_POLICY_SHA256 = "cf7352b1336c2b64220c2f3250541967cd42bcbf67ed9c900880c5c387745d9e"


def _reviewed_policy_bytes(policy_dir: Path) -> bytes | None:
    policy = policy_dir / "kubernetes.rego"
    try:
        if not stat.S_ISREG(policy.lstat().st_mode):
            return None
        content = policy.read_bytes()
        return content if hashlib.sha256(content).hexdigest() == REVIEWED_POLICY_SHA256 else None
    except OSError:
        return None


def _run(argv: list[str], name: str, cwd: Path | None = None) -> GateResult:
    try:
        p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=45, check=False)
    except (OSError, subprocess.SubprocessError):
        return GateResult(name, "FAIL", "Scanner could not complete. Check installation and rerun validation.")
    detail = f"Scanner exit code: {p.returncode}. Run the scanner locally for details."
    return GateResult(name, "PASS" if p.returncode == 0 else "FAIL", detail)

def validate_candidate(candidate: dict, policy_dir: Path | None = None) -> tuple[list[GateResult], bool]:
    policy_dir = policy_dir if policy_dir is not None else Path("policies")
    residual = analyze(candidate)
    gates = [GateResult("builtin-policy", "PASS" if not residual else "FAIL", "; ".join(f.rule for f in residual))]
    with tempfile.TemporaryDirectory(prefix="gitops-medic-") as td:
        candidate_path = Path(td) / "candidate.json"
        candidate_path.write_text(json.dumps(candidate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        reviewed_policy = _reviewed_policy_bytes(policy_dir)
        if shutil.which("conftest") and reviewed_policy is not None:
            staged_policy_dir = Path(td) / "reviewed-policies"
            staged_policy_dir.mkdir()
            (staged_policy_dir / "kubernetes.rego").write_bytes(reviewed_policy)
            gates.append(_run(["conftest", "test", str(candidate_path), "-p", str(staged_policy_dir)], "conftest", cwd=Path(td)))
        else:
            gates.append(GateResult("conftest", "NOT RUN", "Required: install Conftest and restore the shipped, digest-verified kubernetes.rego policy. Policy changes require review and a matching digest update."))
        if shutil.which("trivy"):
            trusted_ignore = Path(td) / "trusted.trivyignore"
            trusted_ignore.write_text("", encoding="utf-8")
            gates.append(_run(["trivy", "config", "--ignorefile", str(trusted_ignore), "--exit-code", "1", "--severity", "HIGH,CRITICAL", str(candidate_path)], "trivy", cwd=Path(td)))
        else:
            gates.append(GateResult("trivy", "NOT RUN", "Required: install Trivy and rerun validation."))
    return gates, all(g.status == "PASS" for g in gates)
