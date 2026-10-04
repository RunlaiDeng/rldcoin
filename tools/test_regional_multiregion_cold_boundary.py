"""Strict terminal gates and actual twelve-store setup inspection, no payments."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
from interstellar_mesh_inspection import MeshInspection
from regional_bft_multiregion_campaign import Campaign
from verify_regional_bft_cycle import inspection_anchors,verify,verify_terminal
from verify_regional_bft_sustained import files


class ColdTerminalTests(unittest.TestCase):
    def completed(self):return dict(completed=True,failure=None,owned_process_cleanup_verified=True,owned_process_shutdown_clean=True)

    def test_failed_unclean_unknown_or_integer_completion_refuses(self):
        for field in ('completed','owned_process_cleanup_verified','owned_process_shutdown_clean'):
            for value in (False,None,1):
                q=self.completed();q[field]=value
                with self.subTest(field=field,value=value),self.assertRaisesRegex(ValueError,'clean terminal'):
                    verify_terminal(q)
        q=self.completed();q['failure']='retained original failure'
        with self.assertRaises(ValueError):verify_terminal(q)

    def test_failed_run_refuses_before_manifest_or_private_access(self):
        with tempfile.TemporaryDirectory() as scratch:
            root=Path(scratch).resolve();report=root/'failed.json';report.write_text(json.dumps(dict(completed=False)))
            from types import SimpleNamespace
            args=SimpleNamespace(source=root/'missing-source',root=root/'missing-private',binary=root/'missing-native',
                                 manifest=root/'missing-manifest',run_report=report)
            with self.assertRaisesRegex(ValueError,'clean terminal'):verify(args)
            self.assertFalse(args.root.exists())

    def test_complete_terminal_is_only_a_gate_not_native_qualification(self):verify_terminal(self.completed())


class ActualSetupInspectionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='rld-three-region-anchors-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()/'fixture'
        self.binary=Path(os.environ['RLD_CONTACT_BINARY']).resolve()
        self.c=Campaign(self.binary,self.root);self.addCleanup(self.c.cleanup)
        self.run=dict(currency=self.c.currency,mesh_inspection_anchors_sha256=self.c.inspection_anchors_sha256)

    def test_all_twelve_actual_stores_inspect_without_node_private_key_or_writes(self):
        before=files(self.root);anchors=inspection_anchors(self.root,self.run)
        self.assertEqual(len(anchors['nodes']),12)
        with patch.object(mesh.Node,'__init__',side_effect=AssertionError('ordinary Node forbidden')),\
             patch.object(mesh,'sign',side_effect=AssertionError('private signing forbidden')),\
             patch.object(mesh,'atomic',side_effect=AssertionError('private write forbidden')):
            for name in ('earth','proxima','andromeda'):
                for n in range(4):
                    config=mesh.load(self.root/f'mesh-config-{name}-{n}.json',65536)
                    with MeshInspection(config,**anchors['nodes'][f'{name}-{n}']) as inspection:
                        self.assertEqual(inspection.id,self.c.node_ids[name,n])
                        self.assertFalse(inspection.summary['native_value_authenticated'])
        self.assertEqual(files(self.root),before)
        for name in ('earth','proxima','andromeda'):
            state=self.c.cli(name,1,'status');self.assertEqual(state['height'],0);self.assertEqual(state['ledger']['minted'],'0')
            signer=self.c.cli(name,1,'bft-status','--signer-dir',self.c.signer(name,1));self.assertEqual(signer['records'],0)
        self.assertEqual(files(self.root),before)

    def test_changed_setup_anchor_refuses_without_private_repair(self):
        path=self.root/'mesh-inspection-anchors.json';value=mesh.load(path,65536);value['network']='a'*64
        mesh.atomic(path,value);before=files(self.root)
        with self.assertRaisesRegex(ValueError,'anchors changed'):inspection_anchors(self.root,self.run)
        self.assertEqual(files(self.root),before)
        with patch.object(mesh.Node,'__init__',side_effect=AssertionError('existing setup must refuse before Node opens')):
            with self.assertRaisesRegex(ValueError,'existing setup'):self.c.pin_inspection_anchors()
        self.assertEqual(files(self.root),before)


if __name__=='__main__':unittest.main()
