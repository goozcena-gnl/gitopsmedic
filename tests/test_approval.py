import os, shutil, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
from gitops_medic.agent import apply_proposal, propose, save_proposal, scan
from gitops_medic.models import GateResult

class ApprovalTests(unittest.TestCase):
    def setUp(self):
        for scanner_patch in (patch('gitops_medic.validator.shutil.which',side_effect=lambda name:name),patch('gitops_medic.validator._run',side_effect=lambda argv,name,**kwargs:GateResult(name,'PASS'))):
            scanner_patch.start(); self.addCleanup(scanner_patch.stop)
        self.td=tempfile.TemporaryDirectory(); self.root=Path(self.td.name)
        shutil.copytree(ROOT/'policies',self.root/'policies')
        self.target=self.root/'deployment.json'; shutil.copy2(ROOT/'examples/insecure/deployment.json',self.target)
        self.old=os.getcwd(); os.chdir(self.root)
    def tearDown(self):
        os.chdir(self.old); self.td.cleanup()
    def test_wrong_approval_is_rejected(self):
        p=propose(Path('deployment.json'),policy_dir=Path('policies'),replacement_image='nginx:1.27.5'); f=save_proposal(p)
        with self.assertRaises(PermissionError): apply_proposal(f,'wrong',repo_root=self.root)
    def test_exact_approval_applies_and_revalidates(self):
        p=propose(Path('deployment.json'),policy_dir=Path('policies'),replacement_image='nginx:1.27.5'); f=save_proposal(p)
        apply_proposal(f,p.proposal_id,repo_root=self.root)
        self.assertEqual(scan(Path('deployment.json')),[])
    def test_stale_source_is_rejected(self):
        p=propose(Path('deployment.json'),policy_dir=Path('policies'),replacement_image='nginx:1.27.5'); f=save_proposal(p)
        self.target.write_text(self.target.read_text()+"\n")
        with self.assertRaises(RuntimeError): apply_proposal(f,p.proposal_id,repo_root=self.root)

if __name__=='__main__': unittest.main()
