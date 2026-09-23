import json, sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
from gitops_medic.analyzer import analyze
from gitops_medic.images import IMAGE_REFERENCE_DIGEST_PINNED, IMAGE_REFERENCE_MUTABLE, IMAGE_REFERENCE_VERSIONED_TAG, image_reference_kind
from gitops_medic.remediator import remediate

TRUSTED_IMAGE="registry.invalid/demo/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

class RemediatorTests(unittest.TestCase):
    def test_remediation_is_deterministic_and_resolves_demo_findings(self):
        m=json.loads((ROOT/'examples/insecure/deployment.json').read_text())
        a=remediate(m,replacement_image=TRUSTED_IMAGE); b=remediate(m,replacement_image=TRUSTED_IMAGE)
        self.assertEqual(a,b)
        self.assertEqual(analyze(a),[])
        self.assertEqual(m['spec']['replicas'],1)

    def test_image_pinning_is_consistent_in_analysis_and_remediation(self):
        digest = "a" * 64
        for image, kind in (
            ("", IMAGE_REFERENCE_MUTABLE),
            ("nginx", IMAGE_REFERENCE_MUTABLE),
            ("nginx:latest", IMAGE_REFERENCE_MUTABLE),
            ("nginx:", IMAGE_REFERENCE_MUTABLE),
            ("nginx:1.27.5", IMAGE_REFERENCE_VERSIONED_TAG),
            ("registry:5000/app", IMAGE_REFERENCE_MUTABLE),
            ("registry.example:5000/team/app", IMAGE_REFERENCE_MUTABLE),
            ("registry:5000/app:", IMAGE_REFERENCE_MUTABLE),
            ("registry:5000/app:latest", IMAGE_REFERENCE_MUTABLE),
            ("registry:5000/app:1.2", IMAGE_REFERENCE_VERSIONED_TAG),
            (f"registry:5000/app@sha256:{digest}", IMAGE_REFERENCE_DIGEST_PINNED),
            (f"nginx:latest@sha256:{digest}", IMAGE_REFERENCE_DIGEST_PINNED),
            (f"bad name@sha256:{digest}", IMAGE_REFERENCE_MUTABLE),
            (f" nginx@sha256:{digest}", IMAGE_REFERENCE_MUTABLE),
            (f"nginx@sha256:{digest} ", IMAGE_REFERENCE_MUTABLE),
            (f"registry:5000//app@sha256:{digest}", IMAGE_REFERENCE_MUTABLE),
            (f"nginx@sha256:{'a' * 63}", IMAGE_REFERENCE_MUTABLE),
            (f"nginx@sha256:{'a' * 65}", IMAGE_REFERENCE_MUTABLE),
            (f"nginx@sha256:{'g' * 64}", IMAGE_REFERENCE_MUTABLE),
            ("registry:5000/app@sha256:", IMAGE_REFERENCE_MUTABLE),
            ("registry:5000/app@sha256:invalid", IMAGE_REFERENCE_MUTABLE),
        ):
            with self.subTest(image=image):
                pinned = kind == IMAGE_REFERENCE_DIGEST_PINNED
                manifest = json.loads((ROOT / "examples/secure/deployment.json").read_text())
                manifest["spec"]["template"]["spec"]["containers"][0]["image"] = image
                self.assertEqual(image_reference_kind(image), kind)
                findings = [finding for finding in analyze(manifest) if finding.rule == "image-not-pinned"]
                self.assertEqual(bool(findings), not pinned)
                if findings:
                    self.assertEqual(findings[0].severity, "HIGH")
                unchanged = remediate(manifest)
                self.assertEqual(unchanged["spec"]["template"]["spec"]["containers"][0]["image"], image)
                self.assertEqual(any(finding.rule == "image-not-pinned" for finding in analyze(unchanged)), not pinned)
                candidate = remediate(manifest, replacement_image=TRUSTED_IMAGE)
                expected = image if pinned else TRUSTED_IMAGE
                self.assertEqual(candidate["spec"]["template"]["spec"]["containers"][0]["image"], expected)
                self.assertFalse(any(finding.rule == "image-not-pinned" for finding in analyze(candidate)))
                self.assertEqual(manifest["spec"]["template"]["spec"]["containers"][0]["image"], image)

if __name__=='__main__': unittest.main()
