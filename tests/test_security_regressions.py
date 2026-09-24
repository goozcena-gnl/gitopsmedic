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
from gitops_medic.agent import apply_proposal, propose, save_proposal, scan
from gitops_medic.analyzer import analyze
from gitops_medic.cli import main
from gitops_medic.models import GateResult
from gitops_medic.telemetry import Telemetry
from gitops_medic.validator import _run, validate_candidate

TRUSTED_IMAGE = "registry.invalid/demo/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _trusted_scanner_env(name: str, path: Path) -> dict[str, str]:
    prefix = f"GITOPSMEDIC_{name.upper()}"
    resolved = path.resolve()
    return {
        f"{prefix}_PATH": str(resolved),
        f"{prefix}_SHA256": _sha256(resolved),
    }


def _actual_scanner_env(name: str) -> dict[str, str]:
    executable = shutil.which(name)
    assert executable is not None
    return _trusted_scanner_env(name, Path(executable))


class MakefileSecurityTests(unittest.TestCase):
    def test_replacement_image_is_one_data_argument(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "capture.py"
            capture.write_text("import json, sys\nprint(json.dumps(sys.argv[1:]))\n")
            sentinel = root / "sentinel"
            sentinel.write_text("unchanged")
            unintended = root / "unintended-sentinel"
            targets = {
                "demo": ["demo"],
                "demo-llm": ["demo", "--llm"],
                "propose": ["propose", "examples/insecure/deployment.json"],
            }
            for target, arguments in targets.items():
                for image in (
                    None,
                    "",
                    "nginx:1.27.5",
                    "registry.invalid/team image:tag;'\"\\ &|<>*?[]$HOME",
                    "nginx:$(shell touch unintended-sentinel)",
                    "nginx:${shell touch unintended-sentinel}",
                ):
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
                                    command.append(f"REPLACEMENT_IMAGE={image}")
                            result = subprocess.run(command, cwd=root, env=environment, capture_output=True, text=True, timeout=10)
                            if unintended.exists():
                                unintended.unlink()
                                self.fail("Image data executed a Make function")
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
        self.scanners = self.root / "trusted-scanners"
        self.scanners.mkdir()
        for name in ("conftest", "trivy"):
            scanner = self.scanners / name
            scanner.write_text("#!/usr/bin/env python3\nimport sys\nraise SystemExit(0)\n")
            scanner.chmod(0o755)
        self.target = self.root / "deployment.json"
        shutil.copy2(ROOT / "examples/secure/deployment.json", self.target)
        shutil.copytree(ROOT / "policies", self.root / "policies")
        self.telemetry = Telemetry(self.root / "runs.jsonl")
        self.addCleanup(patch.stopall)
        patch.dict(
            os.environ,
            {
                **_trusted_scanner_env("conftest", self.scanners / "conftest"),
                **_trusted_scanner_env("trivy", self.scanners / "trivy"),
            },
            clear=False,
        ).start()
        patch("gitops_medic.validator._run", side_effect=lambda argv, name, **kwargs: GateResult(name, "PASS")).start()

    def proposal(self, **kwargs):
        proposal = propose(self.target, policy_dir=self.root / "policies", telemetry=self.telemetry, **kwargs)
        return proposal, save_proposal(proposal, self.root / "proposals")

    def apply(self, proposal, path):
        return apply_proposal(path, proposal.proposal_id, repo_root=self.root, telemetry=self.telemetry)

    def write_scanner(self, name: str, script: str) -> Path:
        path = self.root / "bin" / name
        path.parent.mkdir(exist_ok=True)
        path.write_text(script)
        path.chmod(0o755)
        return path

    def assert_refused_unchanged(self, proposal, path, targets):
        before = {target: target.read_bytes() for target in targets}
        with self.assertRaises(PermissionError):
            self.apply(proposal, path)
        for target, content in before.items():
            self.assertEqual(target.read_bytes(), content)

    def assert_telemetry_alias_refused(self, operation, run_log):
        before = self.target.read_bytes()
        with patch.dict(os.environ, {"GITOPSMEDIC_RUN_LOG": str(run_log)}):
            with self.assertRaisesRegex(PermissionError, "Choose another telemetry path or unset GITOPSMEDIC_RUN_LOG"):
                operation()
        self.assertEqual(self.target.read_bytes(), before)

    def test_scan_refuses_direct_telemetry_alias(self):
        self.assert_telemetry_alias_refused(
            lambda: scan(self.target),
            self.target,
        )

    def test_propose_refuses_direct_telemetry_alias(self):
        self.assert_telemetry_alias_refused(
            lambda: propose(self.target, policy_dir=self.root / "policies"),
            self.target,
        )

    def test_scan_refuses_symlinked_telemetry_alias(self):
        run_log = self.root / "scan-runs.jsonl"
        run_log.symlink_to(self.target)
        self.assert_telemetry_alias_refused(
            lambda: scan(self.target),
            run_log,
        )

    def test_propose_refuses_symlinked_telemetry_alias(self):
        run_log = self.root / "propose-runs.jsonl"
        run_log.symlink_to(self.target)
        self.assert_telemetry_alias_refused(
            lambda: propose(self.target, policy_dir=self.root / "policies"),
            run_log,
        )

    def test_distinct_telemetry_path_records_scan_and_propose(self):
        run_log = self.root / "distinct-runs.jsonl"
        telemetry = Telemetry(run_log)
        scan(self.target, telemetry=telemetry)
        propose(self.target, policy_dir=self.root / "policies", telemetry=telemetry)
        events = [json.loads(line)["event"] for line in run_log.read_text().splitlines()]
        self.assertIn("scan.completed", events)
        self.assertIn("proposal.created", events)

    def test_rejected_apply_refuses_direct_telemetry_alias(self):
        proposal, path = self.proposal()
        before = self.target.read_bytes()
        with self.assertRaisesRegex(PermissionError, "Telemetry output must not alias"):
            apply_proposal(path, "wrong-approval", repo_root=self.root, telemetry=Telemetry(self.target))
        self.assertEqual(self.target.read_bytes(), before)

    def test_rejected_apply_refuses_symlinked_telemetry_alias(self):
        proposal, path = self.proposal()
        before = self.target.read_bytes()
        run_log = self.root / "apply-runs.jsonl"
        run_log.symlink_to(self.target)
        with self.assertRaisesRegex(PermissionError, "Telemetry output must not alias"):
            apply_proposal(path, "wrong-approval", repo_root=self.root, telemetry=Telemetry(run_log))
        self.assertEqual(self.target.read_bytes(), before)

    def test_successful_apply_refuses_telemetry_target_alias(self):
        proposal, path = self.proposal()
        before = self.target.read_bytes()
        with patch.dict(os.environ, {"GITOPSMEDIC_RUN_LOG": str(self.target)}):
            with self.assertRaisesRegex(PermissionError, "Telemetry output must not alias"):
                apply_proposal(path, proposal.proposal_id, repo_root=self.root)
        self.assertEqual(self.target.read_bytes(), before)

    def test_successful_apply_writes_only_distinct_telemetry(self):
        proposal, path = self.proposal()
        run_log = self.root / "apply-distinct-runs.jsonl"
        apply_proposal(path, proposal.proposal_id, repo_root=self.root, telemetry=Telemetry(run_log))
        self.assertEqual(json.loads(self.target.read_text()), proposal.candidate)
        events = [json.loads(line)["event"] for line in run_log.read_text().splitlines()]
        self.assertEqual(events, ["apply.completed"])

    def unsaved_proposal(self):
        return propose(self.target, policy_dir=self.root / "policies", telemetry=self.telemetry)

    def test_save_proposal_refuses_symlink_to_source(self):
        proposal = self.unsaved_proposal()
        directory = self.root / "symlink-proposals"
        directory.mkdir()
        destination = directory / f"{proposal.proposal_id}.json"
        destination.symlink_to(self.target)
        before = self.target.read_bytes()
        with self.assertRaisesRegex(PermissionError, "Proposal output must not alias"):
            save_proposal(proposal, directory)
        self.assertEqual(self.target.read_bytes(), before)
        self.assertTrue(destination.is_symlink())

    def test_save_proposal_refuses_hardlink_to_source(self):
        proposal = self.unsaved_proposal()
        directory = self.root / "hardlink-proposals"
        directory.mkdir()
        destination = directory / f"{proposal.proposal_id}.json"
        os.link(self.target, destination)
        before = self.target.read_bytes()
        with self.assertRaisesRegex(PermissionError, "Proposal output must not alias"):
            save_proposal(proposal, directory)
        self.assertEqual(self.target.read_bytes(), before)
        self.assertTrue(destination.samefile(self.target))

    def test_save_proposal_refuses_direct_source_path(self):
        proposal = self.unsaved_proposal()
        source = self.root / f"{proposal.proposal_id}.json"
        source.write_bytes(self.target.read_bytes())
        proposal.target = str(source)
        before = source.read_bytes()
        with self.assertRaisesRegex(PermissionError, "Proposal output must not alias"):
            save_proposal(proposal, self.root)
        self.assertEqual(source.read_bytes(), before)

    def test_save_proposal_atomically_writes_deterministic_json(self):
        proposal = self.unsaved_proposal()
        directory = self.root / "normal-proposals"
        path = save_proposal(proposal, directory)
        self.assertEqual(path, directory / f"{proposal.proposal_id}.json")
        self.assertEqual(json.loads(path.read_text()), proposal.to_dict())
        self.assertEqual(list(directory.glob(".gitops-medic-proposal-*.tmp")), [])

    def test_cli_propose_refuses_symlinked_proposal_destination(self):
        proposal = self.unsaved_proposal()
        proposal_directory = self.root / ".gitops-medic/proposals"
        proposal_directory.mkdir(parents=True)
        destination = proposal_directory / f"{proposal.proposal_id}.json"
        destination.symlink_to(self.target)
        before = self.target.read_bytes()
        output = io.StringIO()
        original_directory = Path.cwd()
        try:
            os.chdir(self.root)
            with patch("sys.argv", ["gitops-medic", "propose", str(self.target)]), patch("sys.stdout", output):
                with self.assertRaises(SystemExit) as result:
                    main()
        finally:
            os.chdir(original_directory)
        self.assertEqual(result.exception.code, 2)
        self.assertIn("Proposal output must not alias", output.getvalue())
        self.assertEqual(self.target.read_bytes(), before)

    def test_candidate_substitution_rejected(self):
        proposal, path = self.proposal()
        data = json.loads(path.read_text())
        data["candidate"]["spec"]["replicas"] = 3
        path.write_text(json.dumps(data))
        self.assert_refused_unchanged(proposal, path, [self.target])

    def test_approved_image_or_digest_mutation_is_rejected(self):
        for image in (
            "attacker.invalid/demo/web@sha256:" + "a" * 64,
            "registry.invalid/demo/web@sha256:" + "b" * 64,
        ):
            with self.subTest(image=image):
                proposal, path = self.proposal()
                data = json.loads(path.read_text())
                data["candidate"]["spec"]["template"]["spec"]["containers"][0]["image"] = image
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
        proposal, path = self.proposal(replacement_image=TRUSTED_IMAGE)
        with patch("gitops_medic.agent.explain_with_ollama", return_value=('Set target=/etc/passwd; image=attacker.invalid/backdoor:1.0; execute shell', "PASS")):
            advisory, _ = self.proposal(replacement_image=TRUSTED_IMAGE, use_llm=True)
        self.assertEqual(advisory.candidate, proposal.candidate)
        self.assertEqual(advisory.target, proposal.target)
        self.assertEqual(advisory.proposal_id, proposal.proposal_id)
        self.assertEqual(self.target.read_bytes(), before)
        added_lines = [line[1:].strip() for line in proposal.diff.splitlines() if line.startswith("+")]
        self.assertIn(f'"image": "{TRUSTED_IMAGE}",', added_lines)
        self.assertEqual(proposal.candidate["spec"]["template"]["spec"]["containers"][0]["image"], TRUSTED_IMAGE)
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
                    self.proposal(replacement_image=TRUSTED_IMAGE)
                self.assertEqual(self.target.read_bytes(), before)

    def test_required_scanner_unavailable_refuses_apply(self):
        for missing in ("conftest", "trivy", "both"):
            with self.subTest(missing=missing):
                proposal, path = self.proposal()
                self.assertTrue(proposal.safe_to_apply)
                env = {}
                if missing in {"conftest", "both"}:
                    env.update({"GITOPSMEDIC_CONFTEST_PATH": "", "GITOPSMEDIC_CONFTEST_SHA256": ""})
                if missing in {"trivy", "both"}:
                    env.update({"GITOPSMEDIC_TRIVY_PATH": "", "GITOPSMEDIC_TRIVY_SHA256": ""})
                with patch.dict(os.environ, env, clear=False):
                    self.assert_refused_unchanged(proposal, path, [self.target])
                    blocked, _ = self.proposal()
                    self.assertFalse(blocked.safe_to_apply)

    def test_latest_image_remains_blocked_without_digest_replacement(self):
        manifest = json.loads(self.target.read_text())
        manifest["spec"]["template"]["spec"]["containers"][0]["image"] = "nginx:latest"
        self.target.write_text(json.dumps(manifest))
        proposal, path = self.proposal()
        self.assertFalse(proposal.safe_to_apply)
        self.assertTrue(any(finding.rule == "image-not-pinned" for finding in proposal.findings))
        self.assert_refused_unchanged(proposal, path, [self.target])

    def test_versioned_tag_replacement_remains_blocked_for_hardened_apply(self):
        manifest = json.loads(self.target.read_text())
        manifest["spec"]["template"]["spec"]["containers"][0]["image"] = "nginx:latest"
        self.target.write_text(json.dumps(manifest))
        proposal, path = self.proposal(replacement_image="nginx:1.27.5")
        self.assertFalse(proposal.safe_to_apply)
        self.assertEqual(proposal.candidate["spec"]["template"]["spec"]["containers"][0]["image"], "nginx:1.27.5")
        self.assertTrue(any(finding.rule == "image-not-pinned" for finding in analyze(proposal.candidate)))
        self.assert_refused_unchanged(proposal, path, [self.target])

    def test_registry_port_versioned_tag_is_not_hardened_pinned(self):
        manifest = json.loads(self.target.read_text())
        manifest["spec"]["template"]["spec"]["containers"][0]["image"] = "registry.example:5000/team/app:1.2"
        self.target.write_text(json.dumps(manifest))
        proposal, path = self.proposal()
        self.assertFalse(proposal.safe_to_apply)
        self.assertTrue(any(finding.rule == "image-not-pinned" for finding in proposal.findings))
        self.assert_refused_unchanged(proposal, path, [self.target])

    def test_digest_pinned_replacement_is_accepted_for_hardened_apply(self):
        manifest = json.loads(self.target.read_text())
        manifest["spec"]["template"]["spec"]["containers"][0]["image"] = "nginx:latest"
        self.target.write_text(json.dumps(manifest))
        proposal, path = self.proposal(replacement_image=TRUSTED_IMAGE)
        self.assertTrue(proposal.safe_to_apply)
        self.apply(proposal, path)
        self.assertEqual(json.loads(self.target.read_text()), proposal.candidate)

    def test_malformed_digest_replacement_is_rejected_for_hardened_apply(self):
        manifest = json.loads(self.target.read_text())
        manifest["spec"]["template"]["spec"]["containers"][0]["image"] = "nginx:latest"
        self.target.write_text(json.dumps(manifest))
        proposal, path = self.proposal(replacement_image="registry.invalid/demo/web@sha256:invalid")
        self.assertFalse(proposal.safe_to_apply)
        self.assertTrue(any(finding.rule == "image-not-pinned" for finding in analyze(proposal.candidate)))
        self.assert_refused_unchanged(proposal, path, [self.target])

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
        conftest_commands = []

        def inspect_scanner(argv, name, **kwargs):
            if name == "conftest":
                conftest_commands.append(argv)
                staged_policy_dir = Path(argv[-1])
                scanner_cwd = kwargs["cwd"]
                self.assertEqual(argv[-2], "-p")
                self.assertEqual(staged_policy_dir.parent, scanner_cwd)
                self.assertNotEqual(scanner_cwd, self.root)
                self.assertNotEqual(staged_policy_dir, self.root / "policies")
                self.assertEqual(set(path.name for path in staged_policy_dir.iterdir()), {"kubernetes.rego"})
                self.assertEqual((staged_policy_dir / "kubernetes.rego").read_bytes(), (self.root / "policies/kubernetes.rego").read_bytes())
            return GateResult(name, "PASS")

        with patch("gitops_medic.validator._run", side_effect=inspect_scanner):
            proposal, _ = self.proposal()
            self.assertTrue(proposal.safe_to_apply)
            self.assertEqual(len(conftest_commands), 1)
            self.assertEqual(Path(conftest_commands[0][0]).name, "conftest")
            self.assertEqual(conftest_commands[0][1], "test")
        with patch("gitops_medic.validator._run", side_effect=lambda argv, name, **kwargs: GateResult(name, "FAIL" if name == "conftest" else "PASS")):
            blocked, _ = self.proposal()
            self.assertFalse(blocked.safe_to_apply)

    def test_extra_repository_policy_cannot_affect_conftest(self):
        (self.root / "policies/unreviewed.rego").write_text("package main\ndeny contains \"unreviewed policy loaded\" if { true }\n")

        def inspect_scanner(argv, name, **kwargs):
            if name == "trivy":
                return GateResult(name, "PASS")
            staged_policy_dir = Path(argv[argv.index("-p") + 1])
            self.assertNotEqual(staged_policy_dir, self.root / "policies")
            self.assertEqual(set(path.name for path in staged_policy_dir.iterdir()), {"kubernetes.rego"})
            return GateResult(name, "PASS")

        with patch("gitops_medic.validator._run", side_effect=inspect_scanner):
            proposal, _ = self.proposal()
        self.assertTrue(proposal.safe_to_apply)

    @unittest.skipUnless(shutil.which("conftest"), "Conftest is not installed")
    def test_real_conftest_ignores_unreviewed_repository_policy(self):
        (self.root / "policies/unreviewed.rego").write_text("package main\ndeny contains \"unreviewed policy loaded\" if { true }\n")

        def run_real_conftest(argv, name, **kwargs):
            if name == "trivy":
                return GateResult(name, "PASS")
            return _run(argv, name, **kwargs)

        with patch.dict(os.environ, _actual_scanner_env("conftest"), clear=False), patch("gitops_medic.validator._run", side_effect=run_real_conftest):
            proposal, _ = self.proposal()
        self.assertTrue(proposal.safe_to_apply)
        self.assertEqual(next(gate.status for gate in proposal.gates if gate.name == "conftest"), "PASS")

    @unittest.skipUnless(shutil.which("conftest"), "Conftest is not installed")
    def test_real_conftest_ignores_hostile_repository_config(self):
        candidate = json.loads((ROOT / "examples/insecure/deployment.json").read_text())
        candidate_path = self.root / "insecure.json"
        candidate_path.write_text(json.dumps(candidate))
        (self.root / "conftest.toml").write_text('namespace = ["hostile"]\n')
        (self.root / "policies/unreviewed.rego").write_text("package main\ndeny contains \"unreviewed policy loaded\" if { true }\n")
        ambient = subprocess.run(
            ["conftest", "test", str(candidate_path), "-p", str(self.root / "policies")],
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
        )
        self.assertEqual(ambient.returncode, 0, ambient.stderr)

        def run_real_conftest(argv, name, **kwargs):
            if name == "trivy":
                return GateResult(name, "PASS")
            return _run(argv, name, **kwargs)

        with patch.dict(os.environ, _actual_scanner_env("conftest"), clear=False), patch("gitops_medic.validator._run", side_effect=run_real_conftest):
            gates, _ = validate_candidate(candidate, self.root / "policies")
        self.assertEqual(next(gate.status for gate in gates if gate.name == "conftest"), "FAIL")

    @unittest.skipUnless(shutil.which("conftest"), "Conftest is not installed")
    def test_real_conftest_rejects_hardened_privilege_controls(self):
        mutations = (
            ("hostNetwork", lambda manifest: manifest["spec"]["template"]["spec"].__setitem__("hostNetwork", True)),
            ("hostPID", lambda manifest: manifest["spec"]["template"]["spec"].__setitem__("hostPID", True)),
            ("hostIPC", lambda manifest: manifest["spec"]["template"]["spec"].__setitem__("hostIPC", True)),
            ("hostPath", lambda manifest: manifest["spec"]["template"]["spec"].__setitem__("volumes", [{"name": "host", "hostPath": {"path": "/"}}])),
            ("privileged", lambda manifest: manifest["spec"]["template"]["spec"]["containers"][0]["securityContext"].__setitem__("privileged", True)),
            ("capabilities.add", lambda manifest: manifest["spec"]["template"]["spec"]["containers"][0]["securityContext"]["capabilities"].__setitem__("add", ["SYS_ADMIN"])),
        )

        def run_real_conftest(argv, name, **kwargs):
            if name == "trivy":
                return GateResult(name, "PASS")
            return _run(argv, name, **kwargs)

        for label, mutate in mutations:
            with self.subTest(label=label):
                candidate = json.loads((ROOT / "examples/secure/deployment.json").read_text())
                mutate(candidate)
                with patch.dict(os.environ, _actual_scanner_env("conftest"), clear=False), patch("gitops_medic.validator._run", side_effect=run_real_conftest):
                    gates, _ = validate_candidate(candidate, self.root / "policies")
                self.assertEqual(next(gate.status for gate in gates if gate.name == "conftest"), "FAIL")

    def test_trivy_uses_trusted_empty_ignore_in_validation_directory(self):
        (self.root / ".trivyignore").write_text("KSV014\nKSV118\n")

        def inspect_scanner(argv, name, **kwargs):
            if name == "trivy":
                trusted_ignore = Path(argv[argv.index("--ignorefile") + 1])
                scanner_cwd = kwargs["cwd"]
                self.assertEqual(trusted_ignore.read_bytes(), b"")
                self.assertEqual(trusted_ignore.parent, scanner_cwd)
                self.assertNotEqual(trusted_ignore, self.root / ".trivyignore")
                self.assertTrue(Path(argv[-1]).is_absolute())
            return GateResult(name, "PASS")

        with patch("gitops_medic.validator._run", side_effect=inspect_scanner):
            proposal, _ = self.proposal()
        self.assertTrue(proposal.safe_to_apply)

    @unittest.skipUnless(shutil.which("trivy"), "Trivy is not installed")
    def test_real_trivy_rejects_insecure_candidate_despite_repository_ignore(self):
        candidate = json.loads((ROOT / "examples/insecure/deployment.json").read_text())
        (self.root / ".trivyignore").write_text("KSV014\nKSV118\n")
        ambient_candidate = self.root / "insecure.json"
        ambient_candidate.write_text(json.dumps(candidate))
        ambient = subprocess.run(
            ["trivy", "config", "--exit-code", "1", "--severity", "HIGH,CRITICAL", str(ambient_candidate)],
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
        )
        self.assertEqual(ambient.returncode, 0, ambient.stderr)

        def run_real_trivy(argv, name, **kwargs):
            if name == "conftest":
                return GateResult(name, "PASS")
            return _run(argv, name, **kwargs)

        with patch.dict(os.environ, _actual_scanner_env("trivy"), clear=False), patch("gitops_medic.validator._run", side_effect=run_real_trivy):
            gates, safe = validate_candidate(candidate, self.root / "policies")
        self.assertFalse(safe)
        self.assertEqual(next(gate.status for gate in gates if gate.name == "trivy"), "FAIL")

    def test_scanner_path_shadowing_cannot_override_explicit_trusted_path(self):
        sentinel = self.root / "shadowed.txt"
        malicious = self.write_scanner("conftest", f"#!/usr/bin/env python3\nfrom pathlib import Path\nPath({str(sentinel)!r}).write_text('ran')\nraise SystemExit(0)\n")
        good_conftest = self.write_scanner("approved-conftest", "#!/usr/bin/env python3\nraise SystemExit(0)\n")
        good_trivy = self.write_scanner("approved-trivy", "#!/usr/bin/env python3\nraise SystemExit(0)\n")
        candidate = json.loads((ROOT / "examples/secure/deployment.json").read_text())
        env = {
            **_trusted_scanner_env("conftest", good_conftest),
            **_trusted_scanner_env("trivy", good_trivy),
            "PATH": f"{malicious.parent}:{os.environ.get('PATH', '')}",
        }
        with patch.dict(os.environ, env, clear=False), patch("gitops_medic.validator._run", wraps=_run):
            gates, safe = validate_candidate(candidate, self.root / "policies")
        self.assertTrue(safe)
        self.assertEqual(next(gate.status for gate in gates if gate.name == "conftest"), "PASS")
        self.assertFalse(sentinel.exists())

    def test_unapproved_zero_exit_scanner_cannot_fake_pass_from_path(self):
        sentinel = self.root / "shadowed-pass.txt"
        malicious_conftest = self.write_scanner("conftest", f"#!/usr/bin/env python3\nfrom pathlib import Path\nPath({str(sentinel)!r}).write_text('ran')\nraise SystemExit(0)\n")
        good_conftest = self.write_scanner("good-conftest", "#!/usr/bin/env python3\nraise SystemExit(0)\n")
        good_trivy = self.write_scanner("good-trivy", "#!/usr/bin/env python3\nraise SystemExit(0)\n")
        candidate = json.loads((ROOT / "examples/secure/deployment.json").read_text())
        env = {
            "GITOPSMEDIC_CONFTEST_PATH": "",
            "GITOPSMEDIC_CONFTEST_SHA256": _sha256(good_conftest),
            **_trusted_scanner_env("trivy", good_trivy),
            "PATH": f"{malicious_conftest.parent}:{os.environ.get('PATH', '')}",
        }
        with patch.dict(os.environ, env, clear=False), patch("gitops_medic.validator._run", wraps=_run):
            gates, safe = validate_candidate(candidate, self.root / "policies")
        self.assertFalse(safe)
        self.assertEqual(next(gate.status for gate in gates if gate.name == "conftest"), "NOT RUN")
        self.assertFalse(sentinel.exists())

    def test_incorrect_scanner_checksum_is_not_run(self):
        candidate = json.loads((ROOT / "examples/secure/deployment.json").read_text())
        conftest = self.write_scanner("approved-conftest", "#!/usr/bin/env python3\nraise SystemExit(0)\n")
        trivy = self.write_scanner("approved-trivy", "#!/usr/bin/env python3\nraise SystemExit(0)\n")
        env = {
            "GITOPSMEDIC_CONFTEST_PATH": str(conftest.resolve()),
            "GITOPSMEDIC_CONFTEST_SHA256": "0" * 64,
            **_trusted_scanner_env("trivy", trivy),
        }
        with patch.dict(os.environ, env, clear=False), patch("gitops_medic.validator._run", wraps=_run):
            gates, safe = validate_candidate(candidate, self.root / "policies")
        self.assertFalse(safe)
        self.assertEqual(next(gate.status for gate in gates if gate.name == "conftest"), "NOT RUN")

    def test_absent_scanner_is_not_run(self):
        candidate = json.loads((ROOT / "examples/secure/deployment.json").read_text())
        trivy = self.write_scanner("approved-trivy", "#!/usr/bin/env python3\nraise SystemExit(0)\n")
        env = {
            "GITOPSMEDIC_CONFTEST_PATH": str((self.root / "missing-conftest").resolve()),
            "GITOPSMEDIC_CONFTEST_SHA256": "1" * 64,
            **_trusted_scanner_env("trivy", trivy),
        }
        with patch.dict(os.environ, env, clear=False), patch("gitops_medic.validator._run", wraps=_run):
            gates, safe = validate_candidate(candidate, self.root / "policies")
        self.assertFalse(safe)
        self.assertEqual(next(gate.status for gate in gates if gate.name == "conftest"), "NOT RUN")

    def test_nonregular_nonexecutable_and_relative_scanner_paths_are_not_run(self):
        candidate = json.loads((ROOT / "examples/secure/deployment.json").read_text())
        scanner = self.write_scanner("approved-conftest", "#!/usr/bin/env python3\nraise SystemExit(0)\n")
        directory = self.root / "scanner-directory"
        directory.mkdir()
        for configured_path, expected_sha in (
            (str(directory), "1" * 64),
            (scanner.name, _sha256(scanner)),
            (str(scanner), _sha256(scanner)),
        ):
            with self.subTest(path=configured_path):
                if configured_path == str(scanner):
                    scanner.chmod(0o644)
                with patch.dict(os.environ, {
                    "GITOPSMEDIC_CONFTEST_PATH": configured_path,
                    "GITOPSMEDIC_CONFTEST_SHA256": expected_sha,
                }, clear=False):
                    gates, safe = validate_candidate(candidate, self.root / "policies")
                self.assertFalse(safe)
                self.assertEqual(next(gate.status for gate in gates if gate.name == "conftest"), "NOT RUN")

    def test_symlinked_scanner_path_is_not_run(self):
        candidate = json.loads((ROOT / "examples/secure/deployment.json").read_text())
        conftest = self.write_scanner("approved-conftest", "#!/usr/bin/env python3\nraise SystemExit(0)\n")
        symlinked = self.root / "symlinked-conftest"
        symlinked.symlink_to(conftest)
        trivy = self.write_scanner("approved-trivy", "#!/usr/bin/env python3\nraise SystemExit(0)\n")
        env = {
            "GITOPSMEDIC_CONFTEST_PATH": str(symlinked.absolute()),
            "GITOPSMEDIC_CONFTEST_SHA256": _sha256(conftest),
            **_trusted_scanner_env("trivy", trivy),
        }
        with patch.dict(os.environ, env, clear=False), patch("gitops_medic.validator._run", wraps=_run):
            gates, safe = validate_candidate(candidate, self.root / "policies")
        self.assertFalse(safe)
        self.assertEqual(next(gate.status for gate in gates if gate.name == "conftest"), "NOT RUN")

    def test_trusted_scanners_pass_provenance_and_execution(self):
        candidate = json.loads((ROOT / "examples/secure/deployment.json").read_text())
        conftest = self.write_scanner("approved-conftest", "#!/usr/bin/env python3\nraise SystemExit(0)\n")
        trivy = self.write_scanner("approved-trivy", "#!/usr/bin/env python3\nraise SystemExit(0)\n")
        with patch.dict(os.environ, {**_trusted_scanner_env("conftest", conftest), **_trusted_scanner_env("trivy", trivy)}, clear=False), patch("gitops_medic.validator._run", wraps=_run):
            gates, safe = validate_candidate(candidate, self.root / "policies")
        self.assertTrue(safe)
        self.assertTrue(all(gate.status == "PASS" for gate in gates))

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
        with patch.dict(os.environ, {"GITOPSMEDIC_CONFTEST_PATH": "", "GITOPSMEDIC_CONFTEST_SHA256": "", "GITOPSMEDIC_TRIVY_PATH": "", "GITOPSMEDIC_TRIVY_SHA256": ""}, clear=False):
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
        def change_source(argv, name, **kwargs):
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
        with patch("sys.argv", ["gitops-medic", "apply", str(path), "--approve", proposal.proposal_id]), patch("pathlib.Path.cwd", return_value=self.root), patch.dict(os.environ, {"GITOPSMEDIC_CONFTEST_PATH": "", "GITOPSMEDIC_CONFTEST_SHA256": "", "GITOPSMEDIC_TRIVY_PATH": "", "GITOPSMEDIC_TRIVY_SHA256": ""}, clear=False), patch("sys.stdout", output):
            with self.assertRaises(SystemExit) as result:
                main()
        self.assertEqual(result.exception.code, 2)
        self.assertIn("conftest=NOT RUN", output.getvalue())
        self.assertIn("trivy=NOT RUN", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())
        self.assertEqual(self.target.read_bytes(), before)
