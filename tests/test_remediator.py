import json, sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
from gitops_medic.analyzer import analyze
from gitops_medic.remediator import remediate

class RemediatorTests(unittest.TestCase):
    def test_remediation_is_deterministic_and_resolves_demo_findings(self):
        m=json.loads((ROOT/'examples/insecure/deployment.json').read_text())
        a=remediate(m); b=remediate(m)
        self.assertEqual(a,b)
        self.assertEqual(analyze(a),[])
        self.assertEqual(m['spec']['replicas'],1)

if __name__=='__main__': unittest.main()
