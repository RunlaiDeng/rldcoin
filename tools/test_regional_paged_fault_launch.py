import dataclasses
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

from regional_paged_fault_launch import Carrier, PHASES, SLOTS, Source, blueprint
from regional_paged_fault_scope import ReplicaPin, Scope


def inputs():
    keys = tuple(f'{n:064x}' for n in range(1, 5))
    replicas = tuple(ReplicaPin(name,n,dict(earth=9,proxima=6,andromeda=8)[name],
                      'a'*64,'b'*64,keys[n],'c'*64) for name,n in SLOTS)
    scope = Scope('d'*64,replicas,(('earth',27),('proxima',24),('andromeda',24)))
    python = Path(sys.executable)
    source = Source('1'*64,'2'*64,'3'*64,'4'*64,'5'*64,'6'*64,
                    hashlib.sha256(python.resolve(strict=True).read_bytes()).hexdigest())
    carriers = tuple(Carrier(name,n,f'{index+10:064x}',f'{index+40:064x}',40000+index)
                     for index,(name,n) in enumerate(SLOTS))
    return dict(reference=scope,source=source,project=Path('/approved-project'),
                protected_roots=(Path('/approved-project/tmp/retained'),),
                fresh_root=Path('/approved-project/tmp/fresh-paged-fault'),fresh_currency='e'*64,
                starts=(('earth',8),('proxima',5),('andromeda',5)),carriers=carriers,
                relay_ports=(41000,41001),binary=Path('/approved-project/retained-cli'),
                python=python,source_owner='7'*64,
                recipient='8'*64,local_recipient='9'*64)


class Tests(unittest.TestCase):
    def test_complete_stages_offline_role_and_funding(self):
        plan = blueprint(**inputs())
        self.assertEqual(len(plan.configs),48)
        self.assertEqual(tuple(dict.fromkeys(c.phase for c in plan.configs)),PHASES)
        self.assertEqual([sum(c.started for c in plan.configs if c.phase==p) for p in PHASES],
                         [11,12,12,12])
        self.assertEqual(plan.missing_leader_gate,9)
        self.assertEqual([(f.region,f.payment,f.input_minimum,f.destination) for f in plan.funding],
                         [('earth',10,11,'proxima'),('proxima',1,2,None),('andromeda',1,2,None)])
        self.assertTrue(all(f.requires_actual_native_input and f.fee==1 and f.maturity==2
                            for f in plan.funding))
        self.assertTrue(plan.native_setup_required)
        self.assertFalse(plan.network_authority)
        self.assertFalse(plan.signing_authority)

    def test_exact_neighbor_and_end_to_end_tls_pins_survive_proxy_cut(self):
        args = inputs();plan = blueprint(**args)
        pins = {(c.region,c.index):c for c in args['carriers']}
        first = [c for c in plan.configs if c.phase==PHASES[0]]
        for c in first:
            mesh=json.loads(c.mesh);self.assertEqual(mesh['network'],plan.currency)
            for contact in mesh['contacts']:
                self.assertEqual(contact['host'],'127.0.0.1')
                target=next(p for p in pins.values() if p.node==contact['peer'])
                self.assertEqual(contact['tls_cert_sha256'],target.certificate)
                if (c.region,c.index,target.region,target.index)==('earth',1,'proxima',1):
                    self.assertEqual(contact['port'],41000)
                elif (c.region,c.index,target.region,target.index)==('proxima',1,'earth',1):
                    self.assertEqual(contact['port'],41001)
                else:self.assertEqual(contact['port'],target.port)
                self.assertTrue((target.region==c.region and abs(target.index-c.index)==1)
                    or (target.index==c.index==1 and abs(('earth','proxima','andromeda').index(
                        target.region)-('earth','proxima','andromeda').index(c.region))==1))

    def test_keyless_phase_keeps_all_native_caller_signer_paths_and_private_keys(self):
        plan=blueprint(**inputs());first={(c.region,c.index):c for c in plan.configs if c.phase==PHASES[0]}
        for c in (c for c in plan.configs if c.phase=='keyless-drain'):
            old=json.loads(first[c.region,c.index].bft);new=json.loads(c.bft)
            for key in ('signer_dir','head_file','state','key','validators','round_timeout','stop_height'):
                self.assertEqual(new[key],old[key])
            self.assertIn('/keyless-absent/',new['key_file'])
            self.assertNotIn('/keyless-absent/',old['key_file'])
            self.assertEqual((new['round_timeout'],new['stop_height']),
                             (60,dict(plan.caps)[c.region]))
            self.assertEqual(c.argv[c.argv.index('--dir')+1],
                             str(Path(plan.root)/c.region/f'native-{c.index}'))
            self.assertFalse(any('insecure' in arg or 'recover' in arg for arg in c.argv))

    def test_mutable_roles_duplicate_endpoints_and_legacy_profile_refuse(self):
        args=inputs()
        changes=[dict(carriers=args['carriers'][::-1]),dict(carriers=args['carriers'][:-1]),
                 dict(relay_ports=(40000,41001)),dict(relay_ports=(True,41001)),
                 dict(fresh_currency=args['reference'].currency),
                 dict(source=dataclasses.replace(args['source'],rules='legacy')),
                 dict(reference=dataclasses.replace(args['reference'],quorum=2)),
                 dict(reference=dataclasses.replace(args['reference'],max_new_heights=25)),
                 dict(reference=dataclasses.replace(args['reference'],native_authority=True)),
                 dict(carriers=(dataclasses.replace(args['carriers'][0],node=args['carriers'][1].node),
                                *args['carriers'][1:])),
                 dict(carriers=(dataclasses.replace(args['carriers'][0],certificate='0'*64),
                                *args['carriers'][1:]))]
        for changed in changes:
            with self.subTest(changed=tuple(changed)):
                with self.assertRaises(ValueError):blueprint(**dict(args,**changed))

    def test_old_fixture_overlap_foreign_workspace_and_missing_gate_cap_refuse(self):
        args=inputs()
        for changed in (dict(fresh_root=Path('/approved-project/tmp/retained/new-run')),
                        dict(fresh_root=Path('/approved-project/tmp')),
                        dict(fresh_root=Path('/other-project/tmp/fresh')),
                        dict(fresh_root=Path('relative')),
                        dict(starts=(('earth',26),('proxima',5),('andromeda',5))),
                        dict(starts=(('earth',True),('proxima',5),('andromeda',5))),
                        dict(starts=(('earth',8),('proxima',24),('andromeda',5)))):
            with self.assertRaises(ValueError):blueprint(**dict(args,**changed))

    def test_explicit_venv_leaf_pin_without_custody_symlink_relaxation(self):
        args=inputs()
        with self.assertRaises(ValueError):
            blueprint(**dict(args,source=dataclasses.replace(args['source'],python_target='f'*64)))
        with tempfile.TemporaryDirectory() as scratch:
            root=Path(scratch).resolve();leaf=root/'python'
            leaf.symlink_to(Path(sys.executable).resolve(strict=True))
            plan=blueprint(**dict(args,python=leaf))
            self.assertEqual(plan.configs[0].argv[-3],str(leaf))
            directory=root/'directory-link';directory.symlink_to(root,target_is_directory=True)
            with self.assertRaises(ValueError):blueprint(**dict(args,python=directory/'python'))


if __name__ == '__main__':
    unittest.main()
