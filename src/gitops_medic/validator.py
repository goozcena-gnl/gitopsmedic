from __future__ import annotations

import os
import hashlib
import json
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .analyzer import analyze
from .models import GateResult


REVIEWED_POLICY_SHA256 = "da64028cc8c46921363637ffe3408647c7ea95c3dacf6c465af4b188eb32719a"
_TRUSTED_SCANNER_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class TrustedScanner:
    name: str
    path: Path
    sha256: str


def _reviewed_policy_bytes(policy_dir: Path) -> bytes | None:
    policy = policy_dir / "kubernetes.rego"
    try:
        if not stat.S_ISREG(policy.lstat().st_mode):
            return None
        content = policy.read_bytes()
        return content if hashlib.sha256(content).hexdigest() == REVIEWED_POLICY_SHA256 else None
    except OSError:
        return None


def _trusted_scanner_env_prefix(name: str) -> str:
    return f"GITOPSMEDIC_{name.upper()}"


def _trusted_scanner_not_run(name: str, detail: str) -> tuple[None, GateResult]:
    return None, GateResult(name, "NOT RUN", detail)


def _trusted_scanner(name: str) -> tuple[TrustedScanner | None, GateResult | None]:
    prefix = _trusted_scanner_env_prefix(name)
    configured_path = os.environ.get(f"{prefix}_PATH", "").strip()
    expected_sha = os.environ.get(f"{prefix}_SHA256", "").strip().lower()
    if not _TRUSTED_SCANNER_SHA256.fullmatch(expected_sha):
        return _trusted_scanner_not_run(name, f"Required: set {prefix}_SHA256 to the reviewed 64-character SHA-256 of a trusted {name} executable.")
    discovered = configured_path or shutil.which(name)
    if not discovered:
        return _trusted_scanner_not_run(name, f"Required: install {name} and either expose it on PATH or set {prefix}_PATH to a reviewed executable matching {prefix}_SHA256.")
    path = Path(discovered)
    if configured_path and not path.is_absolute():
        return _trusted_scanner_not_run(name, f"Required: set {prefix}_PATH to an absolute path for the trusted {name} executable.")
    try:
        resolved = path.resolve(strict=True)
        info = resolved.lstat()
        if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
            return _trusted_scanner_not_run(name, f"Trusted {name} path must resolve to an executable regular file.")
        actual_sha = hashlib.sha256(resolved.read_bytes()).hexdigest()
    except OSError:
        return _trusted_scanner_not_run(name, f"Trusted {name} provenance could not be verified. Review the local path and SHA-256 configuration before rerunning validation.")
    if actual_sha != expected_sha:
        return _trusted_scanner_not_run(name, f"Trusted {name} provenance mismatch. Review the executable selected by {prefix}_PATH/PATH and update {prefix}_SHA256 only after independent verification.")
    return TrustedScanner(name, resolved, actual_sha), None


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
        conftest, conftest_gate = _trusted_scanner("conftest")
        if conftest is not None and reviewed_policy is not None:
            staged_policy_dir = Path(td) / "reviewed-policies"
            staged_policy_dir.mkdir()
            (staged_policy_dir / "kubernetes.rego").write_bytes(reviewed_policy)
            gates.append(_run([str(conftest.path), "test", str(candidate_path), "-p", str(staged_policy_dir)], "conftest", cwd=Path(td)))
        elif reviewed_policy is None:
            gates.append(GateResult("conftest", "NOT RUN", "Required: restore the shipped, digest-verified kubernetes.rego policy and configure a trusted Conftest executable with GITOPSMEDIC_CONFTEST_SHA256. Policy changes require review and a matching digest update."))
        else:
            gates.append(conftest_gate)
        trivy, trivy_gate = _trusted_scanner("trivy")
        if trivy is not None:
            trusted_ignore = Path(td) / "trusted.trivyignore"
            trusted_ignore.write_text("", encoding="utf-8")
            gates.append(_run([str(trivy.path), "config", "--ignorefile", str(trusted_ignore), "--exit-code", "1", "--severity", "HIGH,CRITICAL", str(candidate_path)], "trivy", cwd=Path(td)))
        else:
            gates.append(trivy_gate)
    return gates, all(g.status == "PASS" for g in gates)
