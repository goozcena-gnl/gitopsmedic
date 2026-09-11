import json, sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
from gitops_medic.analyzer import analyze

class AnalyzerTests(unittest.TestCase):
    def test_insecure_finds_expected_rules(self):
        m=json.loads((ROOT/'examples/insecure/deployment.json').read_text())
        self.assertEqual(sorted(f.rule for f in analyze(m)), sorted([
            'availability-replicas','image-not-pinned','no-privilege-escalation',
            'pod-run-as-non-root','readonly-rootfs','resources-required']))
    def test_secure_has_no_findings(self):
        m=json.loads((ROOT/'examples/secure/deployment.json').read_text())
        self.assertEqual(analyze(m),[])

if __name__=='__main__': unittest.main()
