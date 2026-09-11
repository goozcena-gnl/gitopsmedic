import hashlib
import io
import json
import os
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
from gitops_medic.cli import main
from gitops_medic.models import GateResult
from gitops_medic.telemetry import Telemetry
from gitops_medic.validator import _run


class MakefileSecurityTests(unittest.TestCase):
    def test_replacement_image_is_one_data_argument(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "capture.py"
            capture.write_text("import json, sys\nprint(json.dumps(sys.argv[1:]))\n")
            sentinel = root / "sentinel"
            sentinel.write_text("unchanged")
            targets = {
                "demo": ["demo"],
                "demo-llm": ["demo", "--llm"],
                "propose": ["propose", "examples/insecure/deployment.json"],
            }
            for target, arguments in targets.items():
                for image in (None, "", "nginx:1.27.5", "registry.invalid/team image:tag;'\"\\ &|<>*?[]$HOME"):
                    for source in ("environment", "command-line"):
                        with self.subTest(target=target, image=image, source=source):
                            environment = os.environ.copy()
                            for name in ("REPLACEMENT_IMAGE", "MAKEFLAGS", "MFLAGS", "MAKELEVEL"):
                                environment.pop(name, None)
                            command = ["make", "--no-print-directory", "-s", "-f", str(ROOT / "Makefile"), "PYTHON=python3 capture.py", target]
                            if image is not None:
                                if source == "environment":
                                    environment["REPLACEMENT_IMAGE"] = image
                                else:
                                    command.append("REPLACEMENT_IMAGE=" + image.replace("$", "$$"))
                            result = subprocess.run(command, cwd=root, env=environment, capture_output=True, text=True, timeout=10)
                            self.assertEqual(result.returncode, 0, result.stderr)
                            expected = ["-m", "gitops_medic", *arguments]
                            if image:
                                expected.extend(["--replacement-image", image])
                            self.assertEqual(json.loads(result.stdout), expected)
                            self.assertEqual(result.stderr, "")
                            self.assertEqual(sentinel.read_text(), "unchanged")
                            self.assertEqual(set(root.iterdir()), {capture, sentinel})


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

    def test_vacuous_or_nonregular_policy_refuses_plan_and_apply(self):
        policy = self.root / "policies/kubernetes.rego"
        reviewed = policy.read_bytes()
        proposal, path = self.proposal()
        for kind, content in (
            ("missing", None),
            ("empty", ""),
            ("whitespace", " \n\t"),
            ("comment-only", "# Reviewed policy\n# deny contains msg if { false }\n"),
            ("package-only", "package main\n"),
            ("no-op", "package main\ndeny contains msg if { false; msg := \"unused\" }\n"),
            ("directory", None),
            ("symlink", None),
            ("fifo", None),
        ):
            with self.subTest(kind=kind):
                policy.unlink()
                try:
                    if content is not None:
                        policy.write_text(content)
                    elif kind == "directory":
                        policy.mkdir()
                    elif kind == "symlink":
                        policy.symlink_to(ROOT / "policies/kubernetes.rego")
                    elif kind == "fifo":
                        os.mkfifo(policy)
                    with patch("gitops_medic.validator._run", return_value=GateResult("trivy", "PASS")) as scanner:
                        blocked, _ = self.proposal()
                        self.assertFalse(blocked.safe_to_apply)
                        self.assertEqual(next(gate.status for gate in blocked.gates if gate.name == "conftest"), "NOT RUN")
                        self.assert_refused_unchanged(proposal, path, [self.target])
                        self.assertTrue(all(call.args[1] == "trivy" for call in scanner.call_args_list))
                finally:
                    if kind == "directory":
                        policy.rmdir()
                    else:
                        policy.unlink(missing_ok=True)
                    policy.write_bytes(reviewed)

    def test_shipped_policy_still_requires_real_conftest_gate(self):
        with patch("gitops_medic.validator._run", side_effect=lambda argv, name: GateResult(name, "PASS")) as scanner:
            proposal, _ = self.proposal()
            self.assertTrue(proposal.safe_to_apply)
            conftest = next(call for call in scanner.call_args_list if call.args[1] == "conftest")
            self.assertEqual(conftest.args[0][:2], ["conftest", "test"])
            self.assertEqual(conftest.args[0][-2:], ["-p", str(self.root / "policies")])
        with patch("gitops_medic.validator._run", side_effect=lambda argv, name: GateResult(name, "FAIL" if name == "conftest" else "PASS")):
            blocked, _ = self.proposal()
            self.assertFalse(blocked.safe_to_apply)

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

    def test_predictable_temp_symlink_never_writes_outside(self):
        outside_directory = tempfile.TemporaryDirectory()
        self.addCleanup(outside_directory.cleanup)
        outside = Path(outside_directory.name) / "outside.txt"
        outside.write_text("outside file must remain unchanged")
        outside_before = outside.read_bytes()
        proposal, path = self.proposal()
        target_before = self.target.read_bytes()
        predictable = self.target.with_suffix(self.target.suffix + ".gitops-medic.tmp")
        predictable.symlink_to(outside)
        try:
            self.apply(proposal, path)
        except PermissionError:
            self.assertEqual(self.target.read_bytes(), target_before)
        else:
            self.assertEqual(json.loads(self.target.read_text()), proposal.candidate)
        self.assertEqual(outside.read_bytes(), outside_before)
        self.assertFalse(self.target.is_symlink())
        self.assertTrue(self.target.is_file())

    def test_nonregular_targets_are_rejected(self):
        for kind in ("symlink", "directory", "fifo"):
            with self.subTest(kind=kind):
                proposal, path = self.proposal()
                original = self.target.read_bytes()
                self.target.unlink()
                other = self.root / "other.json"
                other.write_bytes(original)
                if kind == "symlink":
                    self.target.symlink_to(other)
                elif kind == "directory":
                    self.target.mkdir()
                else:
                    os.mkfifo(self.target)
                with self.assertRaisesRegex(PermissionError, "regular file"):
                    self.apply(proposal, path)
                self.assertEqual(other.read_bytes(), original)
                if kind == "directory":
                    self.target.rmdir()
                else:
                    self.target.unlink()
                self.target.write_bytes(original)

    def test_outside_target_refused_even_with_matching_approval(self):
        outside_directory = tempfile.TemporaryDirectory()
        self.addCleanup(outside_directory.cleanup)
        outside = Path(outside_directory.name) / "deployment.json"
        outside.write_bytes(self.target.read_bytes())
        before = outside.read_bytes()
        proposal = propose(outside, policy_dir=self.root / "policies", telemetry=self.telemetry)
        path = save_proposal(proposal, self.root / "proposals")
        self.assert_refused_unchanged(proposal, path, [self.target, outside])
        self.assertEqual(outside.read_bytes(), before)

    def test_atomic_failure_cleans_temp_and_preserves_target(self):
        for operation in ("os.replace", "os.fsync"):
            with self.subTest(operation=operation):
                proposal, path = self.proposal()
                before = self.target.read_bytes()
                with patch(f"gitops_medic.agent.{operation}", side_effect=OSError("injected write failure")):
                    with self.assertRaises(OSError):
                        self.apply(proposal, path)
                self.assertEqual(self.target.read_bytes(), before)
                self.assertEqual(list(self.root.glob(".gitops-medic-*.tmp")), [])

    def test_source_change_during_validation_refused(self):
        proposal, path = self.proposal()
        changed = self.target.read_bytes() + b"\n"
        def change_source(argv, name):
            self.target.write_bytes(changed)
            return GateResult(name, "PASS")
        with patch("gitops_medic.validator._run", side_effect=change_source):
            with self.assertRaisesRegex(RuntimeError, "changed during validation"):
                self.apply(proposal, path)
        self.assertEqual(self.target.read_bytes(), changed)
        self.assertEqual(list(self.root.glob(".gitops-medic-*.tmp")), [])

    def test_atomic_success_preserves_mode_and_cleans_temp(self):
        self.target.chmod(0o640)
        proposal, path = self.proposal()
        self.apply(proposal, path)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o640)
        self.assertEqual(json.loads(self.target.read_text()), proposal.candidate)
        self.assertEqual(list(self.root.glob(".gitops-medic-*.tmp")), [])

    def test_canonical_content_ignores_json_key_order(self):
        proposal, path = self.proposal()
        data = json.loads(path.read_text())
        data["candidate"] = dict(reversed(list(data["candidate"].items())))
        path.write_text(json.dumps(data, separators=(",", ":")))
        self.apply(proposal, path)
        self.assertEqual(json.loads(self.target.read_text()), proposal.candidate)

    def test_recomputed_tampered_token_does_not_match_original_approval(self):
        from gitops_medic.agent import proposal_digest
        proposal, path = self.proposal()
        data = json.loads(path.read_text())
        data["candidate"]["spec"]["replicas"] = 3
        data["proposal_id"] = proposal_digest(data["source_sha256"], Path(data["target"]), data["candidate"])
        path.write_text(json.dumps(data))
        self.assert_refused_unchanged(proposal, path, [self.target])

    def test_cli_missing_gate_reports_actionable_refusal(self):
        proposal, path = self.proposal()
        before = self.target.read_bytes()
        output = io.StringIO()
        with patch("sys.argv", ["gitops-medic", "apply", str(path), "--approve", proposal.proposal_id]), patch("pathlib.Path.cwd", return_value=self.root), patch("gitops_medic.validator.shutil.which", return_value=None), patch("sys.stdout", output):
            with self.assertRaises(SystemExit) as result:
                main()
        self.assertEqual(result.exception.code, 2)
        self.assertIn("conftest=NOT RUN", output.getvalue())
        self.assertIn("trivy=NOT RUN", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())
        self.assertEqual(self.target.read_bytes(), before)