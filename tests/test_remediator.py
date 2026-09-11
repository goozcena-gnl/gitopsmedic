import json, sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
from gitops_medic.analyzer import analyze
from gitops_medic.remediator import remediate

class RemediatorTests(unittest.TestCase):
    def test_remediation_is_deterministic_and_resolves_demo_findings(self):
        m=json.loads((ROOT/'examples/insecure/deployment.json').read_text())
        a=remediate(m,replacement_image='nginx:1.27.5'); b=remediate(m,replacement_image='nginx:1.27.5')
        self.assertEqual(a,b)
        self.assertEqual(analyze(a),[])
        self.assertEqual(m['spec']['replicas'],1)

    def test_image_pinning_is_consistent_in_analysis_and_remediation(self):
        digest = "a" * 64
        for image, pinned in (
            ("", False),
            ("nginx", False),
            ("nginx:latest", False),
            ("nginx:", False),
            ("nginx:1.27.5", True),
            ("registry:5000/app", False),
            ("registry.example:5000/team/app", False),
            ("registry:5000/app:", False),
            ("registry:5000/app:latest", False),
            ("registry:5000/app:1.2", True),
            (f"registry:5000/app@sha256:{digest}", True),
            (f"nginx:latest@sha256:{digest}", True),
            ("registry:5000/app@sha256:", False),
            ("registry:5000/app@sha256:invalid", False),
        ):
            with self.subTest(image=image):
                manifest = json.loads((ROOT / "examples/secure/deployment.json").read_text())
                manifest["spec"]["template"]["spec"]["containers"][0]["image"] = image
                findings = [finding for finding in analyze(manifest) if finding.rule == "image-not-pinned"]
                self.assertEqual(bool(findings), not pinned)
                if findings:
                    self.assertEqual(findings[0].severity, "HIGH")
                unchanged = remediate(manifest)
                self.assertEqual(unchanged["spec"]["template"]["spec"]["containers"][0]["image"], image)
                self.assertEqual(any(finding.rule == "image-not-pinned" for finding in analyze(unchanged)), not pinned)
                candidate = remediate(manifest, replacement_image="nginx:1.27.5")
                expected = image if pinned else "nginx:1.27.5"
                self.assertEqual(candidate["spec"]["template"]["spec"]["containers"][0]["image"], expected)
                self.assertFalse(any(finding.rule == "image-not-pinned" for finding in analyze(candidate)))
                self.assertEqual(manifest["spec"]["template"]["spec"]["containers"][0]["image"], image)

if __name__=='__main__': unittest.main()
