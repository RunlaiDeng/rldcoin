from pathlib import Path
import json,tempfile,time,unittest
from types import SimpleNamespace
import interstellar_mesh as mesh
from regional_paged_fault_driver import Driver
from regional_paged_fault_launch import Config,PHASES,SLOTS
from regional_paged_fault_scope import inventory
from regional_bft_node import private

class KeylessDirectoryTests(unittest.TestCase):
    def model(self, directory):
        d=Driver.__new__(Driver);d.root=directory/'root';d.root.mkdir(mode=0o700);d.output=directory/'output';d.currency='1'*64;d.deadline=time.monotonic()+600
        d.mesh_anchors={s:dict(public_key='2'*64,node_id='3'*64,network=d.currency,config_sha256='4'*64) for s in SLOTS}
        d.configs={}
        for phase in PHASES:
            for label,n in SLOTS:
                key=d.root/'keyless-absent'/f'{label}-{n}.json' if phase==PHASES[-1] else d.root/label/f'public-fixture-key-{n}.json'
                d.configs[phase,label,n]=Config(phase,label,n,True,b'{}',json.dumps(dict(key_file=str(key))).encode(),('never-executed',))
        d.bound=SimpleNamespace(configs=tuple(d.configs.values()),preparation_inventory='5'*64);d.prepared_inventory=inventory(d.root);d.fake_reads=[]
        def status(label,n,command,*args):
            self.assertEqual(command,'status');d.fake_reads.append((label,n));return {'modeled_only':True}
        d.call=status
        return d
    def test_actual_materialization_all12_private_missing_key_paths_without_any_key(self):
        with tempfile.TemporaryDirectory(dir='/Users/galaxy/GitHub/rldcoin/tmp',prefix='keyless-directory-model-') as t:
            d=self.model(Path(t));d.materialize();parent=d.root/'keyless-absent'
            for label,n in SLOTS:
                key=parent/f'{label}-{n}.json';self.assertEqual(private(key,missing=True),key);self.assertFalse(key.exists())
            self.assertEqual(parent.stat().st_mode&0o777,0o700);self.assertEqual(list(parent.iterdir()),[])
            self.assertEqual(d.fake_reads,list(SLOTS))
            with self.assertRaises(ValueError):d.materialize()
    def test_foreign_key_paths_and_preexisting_directory_refuse_before_fake_native_reads(self):
        for reason in ('existing','foreign','symlink'):
            with self.subTest(reason=reason),tempfile.TemporaryDirectory(dir='/Users/galaxy/GitHub/rldcoin/tmp',prefix='keyless-directory-model-') as t:
                d=self.model(Path(t));p=d.root/'keyless-absent'
                if reason=='existing':p.mkdir(mode=0o700)
                elif reason=='symlink':p.symlink_to(d.root/'elsewhere',target_is_directory=True)
                else:
                    c=d.configs[PHASES[-1],'earth',0];d.configs[PHASES[-1],'earth',0]=Config(c.phase,c.region,c.index,c.started,c.mesh,json.dumps(dict(key_file=str(d.root/'earth/public-fixture-key-0.json'))).encode(),c.argv)
                with self.assertRaises((ValueError,FileExistsError)):d.prepare_keyless_directory()
                self.assertFalse(d.fake_reads)
    def test_original_runtime_private_permissions_and_symlink_guards_still_refuse(self):
        with tempfile.TemporaryDirectory(dir='/Users/galaxy/GitHub/rldcoin/tmp',prefix='keyless-directory-model-') as t:
            d=self.model(Path(t));d.materialize();p=d.root/'keyless-absent';p.chmod(0o755)
            with self.assertRaises(ValueError):private(p/'earth-0.json',missing=True)
            p.chmod(0o700);(p/'earth-0.json').symlink_to(p/'nonexistent')
            with self.assertRaises(ValueError):private(p/'earth-0.json',missing=True)
