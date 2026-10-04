"""Cold configuration tampering cannot change native roles or carrier custody."""
import copy
from pathlib import Path
import tempfile
import unittest

from regional_contact_campaign import public
from verify_regional_bft_role_lifecycle import verify_role_mapping, verify_absent_role_custody


class ColdRoleMappingTests(unittest.TestCase):
    def setUp(self):
        self.ids=[str(n+1)*64 for n in range(5)]
        memberships=[[(10,0),(11,1),(12,2),(13,3)],
                     [(62,0),(11,1),(12,2),(13,3)],[(62,0),(12,2),(13,3),(63,4)]]
        self.maps=[sorted([dict(key=public(seed),node_id=self.ids[n]) for seed,n in era],key=lambda r:r['key'])
                   for era in memberships]
        self.anchors=dict(role_validators=self.maps,nodes={str(n):dict(node_id=i) for n,i in enumerate(self.ids)})
        self.context=dict(initial_keys=[r['key'] for r in self.maps[0]],
                          epochs=[dict(statement=dict(validators=[r['key'] for r in m])) for m in self.maps[1:]])

    def config(self,n):
        slots=[]
        for number,mapping in enumerate(self.maps):
            key=next((r['key'] for r in mapping if r['node_id']==self.ids[n]),None)
            slots.append(None if key is None or number==0 and n==0 else dict(key=key))
        return dict(validators=copy.deepcopy(self.maps[0]),initial_slot=slots[0],
                    handoffs=[dict(validators=copy.deepcopy(m),slot=slot) for m,slot in zip(self.maps[1:],slots[1:])])

    def test_actual_join_continue_depart_slot_shapes_match_certified_memberships(self):
        for n in range(5):verify_role_mapping(self.config(n),self.context,self.anchors,self.ids[n])

    def test_changed_carrier_mapping_refuses_even_with_same_certified_keys(self):
        config=self.config(2);config['handoffs'][1]['validators'][0]['node_id']=self.ids[1]
        with self.assertRaisesRegex(ValueError,'setup anchors'):
            verify_role_mapping(config,self.context,self.anchors,self.ids[2])

    def test_config_and_setup_agreement_cannot_replace_native_signed_membership(self):
        config=self.config(2);anchors=copy.deepcopy(self.anchors)
        config['handoffs'][1]['validators'][0]['key']=public(64)
        anchors['role_validators'][2]=copy.deepcopy(config['handoffs'][1]['validators'])
        with self.assertRaisesRegex(ValueError,'native certified membership'):
            verify_role_mapping(config,self.context,anchors,self.ids[2])

    def test_retired_or_foreign_slot_cannot_borrow_another_carriers_custody(self):
        for n in (1,2,4):
            config=self.config(n);config['handoffs'][1]['slot']=dict(key=public(11))
            with self.assertRaisesRegex(ValueError,'local role slot'):
                verify_role_mapping(config,self.context,self.anchors,self.ids[n])

    def test_absent_new_slots_keep_historical_custody(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'role-voter-1-1').mkdir()
            (root/'role-ready-caller-1-1').mkdir()
            for n,era in ((1,2),(4,1)):
                rows=verify_absent_role_custody(root,self.config(n),n)
                self.assertEqual(rows,[dict(carrier=n,era=era,paths_checked=4,
                                           paths_absent=True,private_slot_initialized=False)])
            self.assertTrue((root/'role-voter-1-1').is_dir())

    def test_every_unconfigured_new_custody_directory_refuses_without_removal(self):
        for stem in ('role-voter','role-ready','role-voter-caller','role-ready-caller'):
            with self.subTest(stem=stem), tempfile.TemporaryDirectory() as directory:
                root=Path(directory);path=root/f'{stem}-2-1';path.mkdir()
                with self.assertRaisesRegex(ValueError,'unexpected custody'):
                    verify_absent_role_custody(root,self.config(1),1)
                self.assertTrue(path.is_dir())

    def test_unconfigured_marker_file_or_dangling_symlink_refuses_unchanged(self):
        for symlink in (False,True):
            with self.subTest(symlink=symlink), tempfile.TemporaryDirectory() as directory:
                root=Path(directory);path=root/'role-voter-2-1'
                if symlink:path.symlink_to(root/'missing-custody')
                else:path.write_bytes(b'RESTORING')
                with self.assertRaisesRegex(ValueError,'unexpected custody'):
                    verify_absent_role_custody(root,self.config(1),1)
                self.assertTrue(path.is_symlink() if symlink else path.read_bytes()==b'RESTORING')

    def test_out_of_scope_carrier_and_handoff_count_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            for n in (-1,5,True):
                with self.assertRaises(ValueError):
                    verify_absent_role_custody(Path(directory),self.config(1),n)
            config=self.config(1);config['handoffs'].pop()
            with self.assertRaises(ValueError):verify_absent_role_custody(Path(directory),config,1)


if __name__=='__main__':unittest.main()
