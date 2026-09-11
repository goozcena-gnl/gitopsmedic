import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from gitops_medic.agent import apply_proposal, propose, save_proposal
from gitops_medic.analyzer import analyze
from gitops_medic.models import GateResult
from gitops_medic.telemetry import Telemetry
from gitops_medic.validator import _run


class SecurityTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.target = self.root / "deployment.json"
        shutil.copy2(ROOT / "examples/secure/deployment.json", self.target)
        shutil.copytree(ROOT / "policies", self.root / "policies")
        self.telemetry = Telemetry(self.root / "runs.jsonl")
        self.addCleanup(patch.stopall)
        patch("gitops_medic.validator.shutil.which", side_effect=lambda name: name).start()
        patch("gitops_medic.validator._run", side_effect=lambda argv, name: GateResult(name, "PASS")).start()

    def proposal(self, **kwargs):
        proposal = propose(self.target, policy_dir=self.root / "policies", telemetry=self.telemetry, **kwargs)
        return proposal, save_proposal(proposal, self.root / "proposals")

    def apply(self, proposal, path):
        return apply_proposal(path, proposal.proposal_id, repo_root=self.root, telemetry=self.telemetry)

    def assert_refused_unchanged(self, proposal, path, targets):
        before = {target: target.read_bytes() for target in targets}
        with self.assertRaises(PermissionError):
            self.apply(proposal, path)
        for target, content in before.items():
            self.assertEqual(target.read_bytes(), content)

    def test_candidate_substitution_rejected(self):
        proposal, path = self.proposal()
        data = json.loads(path.read_text())
        data["candidate"]["spec"]["replicas"] = 3
        path.write_text(json.dumps(data))
        self.assert_refused_unchanged(proposal, path, [self.target])

    def test_target_substitution_rejected(self):
        proposal, path = self.proposal()
        other = self.root / "other.json"
        other.write_bytes(self.target.read_bytes() + b"\n")
        data = json.loads(path.read_text())
        data["target"] = str(other)
        data["source_sha256"] = hashlib.sha256(other.read_bytes()).hexdigest()
        path.write_text(json.dumps(data))
        self.assert_refused_unchanged(proposal, path, [self.target, other])

    def test_unsafe_proposal_cannot_be_authorized_by_serialized_flag(self):
        manifest = json.loads(self.target.read_text())
        manifest["spec"]["template"]["spec"]["containers"][0]["image"] = "nginx:latest"
        manifest["metadata"].pop("annotations", None)
        self.target.write_text(json.dumps(manifest))
        proposal, path = self.proposal()
        self.assertFalse(proposal.safe_to_apply)
        data = json.loads(path.read_text())
        data["candidate"]["spec"]["template"]["spec"]["containers"][0]["image"] = "attacker.invalid/backdoor:1.0"
        data["safe_to_apply"] = True
        path.write_text(json.dumps(data))
        self.assert_refused_unchanged(proposal, path, [self.target])

    def test_manifest_annotation_cannot_choose_replacement(self):
        manifest = json.loads(self.target.read_text())
        manifest["metadata"]["annotations"] = {"gitops-medic.dev/safe-image": "attacker.invalid/backdoor:1.0"}
        manifest["spec"]["template"]["spec"]["containers"][0]["image"] = "nginx:latest"
        self.target.write_text(json.dumps(manifest))
        before = self.target.read_bytes()
        proposal, path = self.proposal()
        self.assertEqual(self.target.read_bytes(), before)
        image = proposal.candidate["spec"]["template"]["spec"]["containers"][0]["image"]
        self.assertNotEqual(image, "attacker.invalid/backdoor:1.0")
        self.assertEqual(image, "nginx:latest")
        self.assertFalse(proposal.safe_to_apply)
        self.assert_refused_unchanged(proposal, path, [self.target])

    def test_trusted_image_is_deterministic_visible_and_llm_independent(self):
        manifest = json.loads(self.target.read_text())
        manifest["metadata"]["annotations"] = {"gitops-medic.dev/safe-image": "attacker.invalid/backdoor:1.0"}
        manifest["spec"]["template"]["spec"]["containers"][0]["image"] = "nginx:latest"
        self.target.write_text(json.dumps(manifest))
        before = self.target.read_bytes()
        proposal, path = self.proposal(replacement_image="nginx:1.27.5")
        with patch("gitops_medic.agent.explain_with_ollama", return_value=('Set target=/etc/passwd; image=attacker.invalid/backdoor:1.0; execute shell', "PASS")):
            advisory, _ = self.proposal(replacement_image="nginx:1.27.5", use_llm=True)
        self.assertEqual(advisory.candidate, proposal.candidate)
        self.assertEqual(advisory.target, proposal.target)
        self.assertEqual(advisory.proposal_id, proposal.proposal_id)
        self.assertEqual(self.target.read_bytes(), before)
        added_lines = [line[1:].strip() for line in proposal.diff.splitlines() if line.startswith("+")]
        self.assertIn('"image": "nginx:1.27.5",', added_lines)
        self.assertEqual(proposal.candidate["spec"]["template"]["spec"]["containers"][0]["image"], "nginx:1.27.5")
        self.apply(proposal, path)
        self.assertEqual(json.loads(self.target.read_text()), proposal.candidate)

    def test_trusted_replacement_rejects_multiple_containers(self):
        for container_kind in ("containers", "initContainers", "ephemeralContainers"):
            with self.subTest(container_kind=container_kind):
                manifest = json.loads((ROOT / "examples/secure/deployment.json").read_text())
                pod_spec = manifest["spec"]["template"]["spec"]
                pod_spec.setdefault(container_kind, []).append({"name": "second", "image": "other:latest"})
                self.target.write_text(json.dumps(manifest))
                before = self.target.read_bytes()
                with self.assertRaisesRegex(ValueError, "one regular container"):
                    self.proposal(replacement_image="nginx:1.27.5")
                self.assertEqual(self.target.read_bytes(), before)

    def test_required_scanner_unavailable_refuses_apply(self):
        for missing in ("conftest", "trivy", "both"):
            with self.subTest(missing=missing):
                proposal, path = self.proposal()
                self.assertTrue(proposal.safe_to_apply)
                with patch("gitops_medic.validator.shutil.which", side_effect=lambda name: None if name == missing or missing == "both" else name):
                    self.assert_refused_unchanged(proposal, path, [self.target])
                    blocked, _ = self.proposal()
                    self.assertFalse(blocked.safe_to_apply)

    def test_missing_policies_refuses_apply(self):
        proposal, path = self.proposal()
        shutil.rmtree(self.root / "policies")
        self.assert_refused_unchanged(proposal, path, [self.target])

    def test_empty_policies_refuses_apply(self):
        proposal, path = self.proposal()
        (self.root / "policies/kubernetes.rego").unlink()
        self.assert_refused_unchanged(proposal, path, [self.target])

    def test_scanner_failure_timeout_and_error_refuse_apply_without_output_leak(self):
        for result in (subprocess.CompletedProcess([], 1, "secret-manifest-content", "untrusted-output"), subprocess.TimeoutExpired("scanner", 45), OSError("sensitive environment")):
            with self.subTest(result=type(result).__name__):
                proposal, path = self.proposal()
                options = {"side_effect": result} if isinstance(result, Exception) else {"return_value": result}
                with patch("gitops_medic.validator._run", wraps=_run), patch("gitops_medic.validator.subprocess.run", **options):
                    self.assert_refused_unchanged(proposal, path, [self.target])
                    blocked, _ = self.proposal()
                    self.assertFalse(blocked.safe_to_apply)
                    serialized = json.dumps([gate.to_dict() for gate in blocked.gates])
                    for sensitive in ("secret-manifest-content", "untrusted-output", "sensitive environment"):
                        self.assertNotIn(sensitive, serialized)

    def test_serialized_safety_is_audit_only(self):
        proposal, path = self.proposal()
        data = json.loads(path.read_text())
        data["safe_to_apply"] = False
        path.write_text(json.dumps(data))
        self.apply(proposal, path)
        self.assertEqual(json.loads(self.target.read_text()), proposal.candidate)
        manifest = json.loads(self.target.read_text())
        manifest["spec"]["template"]["spec"]["hostNetwork"] = True
        self.target.write_text(json.dumps(manifest))
        proposal, path = self.proposal()
        data = json.loads(path.read_text())
        data["safe_to_apply"] = True
        data["gates"] = [{"name": "builtin-policy", "status": "PASS"}]
        path.write_text(json.dumps(data))
        self.assert_refused_unchanged(proposal, path, [self.target])

    def test_privileged_hostpath_with_scanners_absent_refuses_apply(self):
        manifest = json.loads(self.target.read_text())
        pod_spec = manifest["spec"]["template"]["spec"]
        pod_spec["containers"][0]["securityContext"]["privileged"] = True
        pod_spec["volumes"] = [{"name": "host", "hostPath": {"path": "/"}}]
        self.target.write_text(json.dumps(manifest))
        with patch("gitops_medic.validator.shutil.which", return_value=None):
            proposal, path = self.proposal()
            self.assertFalse(proposal.safe_to_apply)
            self.assertEqual(proposal.gates[0].status, "FAIL")
            self.assert_refused_unchanged(proposal, path, [self.target])

    def test_dangerous_pod_privileges_refuse_apply(self):
        for field, value, rule in (
            ("hostNetwork", True, "host-network"),
            ("hostPID", True, "host-pid"),
            ("hostIPC", True, "host-ipc"),
            ("volumes", [{"name": "host", "hostPath": {"path": "/"}}], "host-path"),
        ):
            with self.subTest(field=field):
                manifest = json.loads((ROOT / "examples/secure/deployment.json").read_text())
                manifest["spec"]["template"]["spec"][field] = value
                self.target.write_text(json.dumps(manifest))
                proposal, path = self.proposal()
                self.assert_refused_unchanged(proposal, path, [self.target])
                self.assertFalse(proposal.safe_to_apply)
                self.assertTrue(any(f.rule == rule and f.severity in {"HIGH", "CRITICAL"} for f in analyze(proposal.candidate)))

    def test_dangerous_container_privileges_refuse_apply(self):
        for container_kind in ("containers", "initContainers", "ephemeralContainers"):
            for context, rule in (({"privileged": True}, "privileged-container"), ({"capabilities": {"add": ["SYS_ADMIN"]}}, "added-capabilities")):
                with self.subTest(container_kind=container_kind, rule=rule):
                    manifest = json.loads((ROOT / "examples/secure/deployment.json").read_text())
                    pod_spec = manifest["spec"]["template"]["spec"]
                    container = json.loads(json.dumps(pod_spec["containers"][0]))
                    container["securityContext"].update(context)
                    pod_spec[container_kind] = [container]
                    self.target.write_text(json.dumps(manifest))
                    proposal, path = self.proposal()
                    self.assert_refused_unchanged(proposal, path, [self.target])
                    self.assertFalse(proposal.safe_to_apply)
                    self.assertTrue(any(f.rule == rule and f.severity in {"HIGH", "CRITICAL"} for f in analyze(proposal.candidate)))