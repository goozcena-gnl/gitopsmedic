from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from pathlib import Path

from .agent import apply_proposal, propose, save_proposal, scan

def _findings_json(findings):
    return json.dumps([f.to_dict() for f in findings], indent=2)

def cmd_scan(args):
    findings = scan(Path(args.target))
    print(_findings_json(findings))
    return 1 if any(f.severity in {"HIGH", "CRITICAL"} for f in findings) else 0

def cmd_propose(args):
    p = propose(Path(args.target), use_llm=args.llm, policy_dir=Path("policies"), replacement_image=args.replacement_image)
    out = save_proposal(p)
    print(p.explanation)
    print("\n--- DIFF ---\n" + (p.diff or "(no changes)"))
    print("Gates:", ", ".join(f"{g.name}={g.status}" for g in p.gates))
    print(f"safe_to_apply={p.safe_to_apply}")
    print(f"proposal_id={p.proposal_id}")
    print(f"proposal_file={out}")
    return 0 if p.safe_to_apply else 2

def cmd_apply(args):
    target = apply_proposal(Path(args.proposal), args.approve)
    print(f"Applied validated proposal to {target}")
    return 0

def cmd_demo(args):
    source = Path("examples/insecure/deployment.json")
    with tempfile.TemporaryDirectory(prefix="gitops-medic-demo-") as td:
        demo_root = Path(td)
        shutil.copytree(Path("policies"), demo_root / "policies")
        target = demo_root / "deployment.json"
        shutil.copy2(source, target)
        p = propose(target, use_llm=args.llm, policy_dir=demo_root / "policies", replacement_image=args.replacement_image)
        propdir = demo_root / ".gitops-medic/proposals"
        prop = save_proposal(p, propdir)
        print("=== GitOpsMedic demo ===")
        print(p.explanation)
        print("\n" + p.diff)
        print("Gates:", ", ".join(f"{g.name}={g.status}" for g in p.gates))
        print(f"Human approval required: --approve {p.proposal_id}")
        apply_proposal(prop, p.proposal_id, repo_root=demo_root)
        remaining = scan(target)
        print(f"Apply complete. Residual built-in findings: {len(remaining)}")
    return 0

def build_parser():
    p = argparse.ArgumentParser(prog="gitops-medic", description="Safety-first CloudOps remediation agent for declarative Kubernetes manifests.")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan"); s.add_argument("target"); s.set_defaults(func=cmd_scan)
    pr = sub.add_parser("propose"); pr.add_argument("target"); pr.add_argument("--llm", action="store_true"); pr.set_defaults(func=cmd_propose)
    pr.add_argument("--replacement-image", help="Operator-reviewed image for one regular container; never sourced from manifest metadata")
    ap = sub.add_parser("apply"); ap.add_argument("proposal"); ap.add_argument("--approve", required=True); ap.set_defaults(func=cmd_apply)
    d = sub.add_parser("demo"); d.add_argument("--llm", action="store_true"); d.set_defaults(func=cmd_demo)
    d.add_argument("--replacement-image", help="Operator-reviewed image for the temporary demo workload")
    return p

def main():
    args = build_parser().parse_args()
    raise SystemExit(args.func(args))

if __name__ == "__main__":
    main()
