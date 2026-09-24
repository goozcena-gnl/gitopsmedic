import os, shutil, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
from gitops_medic.agent import apply_proposal, propose, save_proposal, scan
from gitops_medic.models import GateResult

TRUSTED_IMAGE="registry.invalid/demo/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

def _sha256(path: Path) -> str:
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()

class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory(); self.root=Path(self.td.name)
        self.scanners=self.root/'trusted-scanners'; self.scanners.mkdir()
        for name in ('conftest','trivy'):
            scanner=self.scanners/name
            scanner.write_text("#!/usr/bin/env python3\nimport sys\nraise SystemExit(0)\n")
            scanner.chmod(0o755)
        trusted_env={
            'GITOPSMEDIC_CONFTEST_PATH':str((self.scanners/'conftest').resolve()),
            'GITOPSMEDIC_CONFTEST_SHA256':_sha256(self.scanners/'conftest'),
            'GITOPSMEDIC_TRIVY_PATH':str((self.scanners/'trivy').resolve()),
            'GITOPSMEDIC_TRIVY_SHA256':_sha256(self.scanners/'trivy'),
        }
        for scanner_patch in (patch.dict(os.environ,trusted_env,clear=False),patch('gitops_medic.validator._run',side_effect=lambda argv,name,**kwargs:GateResult(name,'PASS'))):
            scanner_patch.start(); self.addCleanup(scanner_patch.stop)
        shutil.copytree(ROOT/'policies',self.root/'policies')
        self.target=self.root/'deployment.json'; shutil.copy2(ROOT/'examples/insecure/deployment.json',self.target)
        self.old=os.getcwd(); os.chdir(self.root)
    def tearDown(self):
        os.chdir(self.old); self.td.cleanup()
    def test_wrong_approval_is_rejected(self):
        p=propose(Path('deployment.json'),policy_dir=Path('policies'),replacement_image=TRUSTED_IMAGE); f=save_proposal(p)
        with self.assertRaises(PermissionError): apply_proposal(f,'wrong',repo_root=self.root)
    def test_exact_approval_applies_and_revalidates(self):
        p=propose(Path('deployment.json'),policy_dir=Path('policies'),replacement_image=TRUSTED_IMAGE); f=save_proposal(p)
        apply_proposal(f,p.proposal_id,repo_root=self.root)
        self.assertEqual(scan(Path('deployment.json')),[])
    def test_stale_source_is_rejected(self):
        p=propose(Path('deployment.json'),policy_dir=Path('policies'),replacement_image=TRUSTED_IMAGE); f=save_proposal(p)
        self.target.write_text(self.target.read_text()+"\n")
        with self.assertRaises(RuntimeError): apply_proposal(f,p.proposal_id,repo_root=self.root)

if __name__=='__main__': unittest.main()
