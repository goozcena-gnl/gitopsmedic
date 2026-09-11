from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from gitops_medic.agent import load_json, propose
from gitops_medic.analyzer import analyze

def main() -> int:
    cfg = json.loads((ROOT / "evals/scenarios.json").read_text())
    passed = 0
    total = 0
    for scenario in cfg["scenarios"]:
        total += 1
        manifest, _ = load_json(ROOT / scenario["path"])
        got = sorted(f.rule for f in analyze(manifest))
        expected = sorted(scenario["expected_rules"])
        ok = got == expected
        passed += int(ok)
        print(f"{'PASS' if ok else 'FAIL'} diagnosis/{scenario['name']}: {got}")
    total += 1
    p = propose(ROOT / "examples/unfixable/deployment.json", policy_dir=ROOT / "policies")
    ok = not p.safe_to_apply
    passed += int(ok)
    print(f"{'PASS' if ok else 'FAIL'} guardrail/unfixable: safe_to_apply={p.safe_to_apply}")
    score = round(100 * passed / total, 1)
    print(f"Evaluation score: {passed}/{total} = {score}%")
    return 0 if passed == total else 1

if __name__ == "__main__":
    raise SystemExit(main())
