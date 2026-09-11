from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from .analyzer import analyze
from .models import GateResult


def _run(argv: list[str], name: str) -> GateResult:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=45, check=False)
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
        if shutil.which("conftest") and policy_dir.is_dir() and any(policy_dir.rglob("*.rego")):
            gates.append(_run(["conftest", "test", str(candidate_path), "-p", str(policy_dir)], "conftest"))
        else:
            gates.append(GateResult("conftest", "NOT RUN", "Required: install Conftest and restore the reviewed policies directory with Rego rules."))
        if shutil.which("trivy"):
            gates.append(_run(["trivy", "config", "--exit-code", "1", "--severity", "HIGH,CRITICAL", str(candidate_path)], "trivy"))
        else:
            gates.append(GateResult("trivy", "NOT RUN", "Required: install Trivy and rerun validation."))
    return gates, all(g.status == "PASS" for g in gates)
