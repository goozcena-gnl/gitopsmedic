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
    except (OSError, subprocess.SubprocessError) as exc:
        return GateResult(name, "FAIL", str(exc))
    detail = (p.stdout + p.stderr).strip()[-2000:]
    return GateResult(name, "PASS" if p.returncode == 0 else "FAIL", detail)

def validate_candidate(candidate: dict, policy_dir: Path | None = None) -> tuple[list[GateResult], bool]:
    residual = analyze(candidate)
    gates = [GateResult("builtin-policy", "PASS" if not residual else "FAIL", "; ".join(f.rule for f in residual))]
    with tempfile.TemporaryDirectory(prefix="gitops-medic-") as td:
        candidate_path = Path(td) / "candidate.json"
        candidate_path.write_text(json.dumps(candidate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if shutil.which("conftest") and policy_dir and policy_dir.exists():
            gates.append(_run(["conftest", "test", str(candidate_path), "-p", str(policy_dir)], "conftest"))
        else:
            gates.append(GateResult("conftest", "NOT_RUN", "binary unavailable or policy directory missing"))
        if shutil.which("trivy"):
            gates.append(_run(["trivy", "config", "--exit-code", "1", "--severity", "HIGH,CRITICAL", str(candidate_path)], "trivy"))
        else:
            gates.append(GateResult("trivy", "NOT_RUN", "binary unavailable"))
    mandatory_ok = gates[0].status == "PASS"
    optional_ok = all(g.status != "FAIL" for g in gates[1:])
    return gates, mandatory_ok and optional_ok
