"""Actual native custody/caller recovery; no mocked approval or ledger authority."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
from regional_bft_role_lifecycle_campaign import Campaign
from regional_bft_node import Runtime
from regional_contact_node import Native
from regional_contact_campaign import public

BINARY=Path(os.environ.get('RLD_CONTACT_BINARY',str(Path(__file__).parent/'regional-ledger/target/debug/rld-regional-ledger-candidate'))).resolve()


class RoleLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='rld-role-lifecycle-')
        self.c=Campaign(BINARY,Path(self.temp.name).resolve()/'fixture')
        current=self.c.cli('earth',1,'bft-context')['context']
        validators=self.c.configs[0]['handoffs'][0]['validators']
        plan=dict(currency=self.c.currency,region=self.c.regions['earth'],previous_epoch=current['epoch'],
                  number=1,validators=[v['key'] for v in validators])
        certificate=self.c.checkpoint('earth',[{'Reconfigure':plan}])
        for n in (0,4):self.c.cli('earth',n,'finalize','--file',self.c.file(f'closing-{n}',certificate))
        for n in (1,2,3):
            path=self.c.root/f'caller-head-{n}/head.json'
            mesh.atomic(path,dict(mesh.load(path,8*1024*1024),head=self.c.heads['earth',n]))
        self.scope=self.c.cli('earth',0,'bft-epoch-proposal')
        self.runtimes={}

    def tearDown(self):
        for runtime in self.runtimes.values():runtime.close()
        self.c.cleanup()
        result=self._outcome.result
        if any(test is self for test,_ in result.failures+result.errors):
            self.temp._finalizer.detach() # Preserve failed private fixture; no key/state output.
        else:self.temp.cleanup()

    def open(self,n=0):
        native=Native(BINARY,self.c.node('earth',n),public(1),self.c.currency)
        runtime=Runtime(native,mesh.load(self.c.root/f'mesh-config-{n}.json',65536),self.c.root/f'bft-config-{n}.json')
        self.runtimes[n]=runtime
        return runtime

    def close(self,n=0):
        self.runtimes.pop(n).close()

    def slot(self,n=0,era=1):return self.c.configs[n]['handoffs'][era-1]['slot']

    def test_joining_only_creates_separate_readiness_without_old_votes_and_restarts(self):
        runtime=self.open();slot=self.slot()
        self.assertIsNone(runtime.key)
        observed=runtime.tick()
        self.assertIsNone(observed['validator'])
        self.assertFalse(observed['autonomous_signing_enabled'])
        status=runtime.native.call('joint-ready-status','--ready-dir',slot['ready_dir'])
        self.assertTrue(status['approved'])
        self.assertEqual(status['binding']['key'],slot['key'])
        self.assertEqual(self.c.cli('earth',0,'bft-status','--signer-dir',self.c.signer('earth',0))['records'],0)
        self.assertFalse(Path(slot['signer_dir']).exists())
        head=Path(slot['ready_head']).read_bytes()
        self.close();restored=self.open()
        self.assertEqual(Path(slot['ready_head']).read_bytes(),head)
        self.assertTrue(any(body.get('EpochApproval',{}).get('role')=='New'
                            for _,body,_,_ in restored.state['messages'].bodies()))

    def test_ready_marker_write_failure_precedes_native_directory_or_signature(self):
        runtime=self.open();slot=self.slot();path=Path(slot['ready_head']);original=path.read_bytes()
        atomic=mesh.atomic
        def fail(target,value):
            if target==path and value.get('initialization') is not None:raise OSError('injected role caller write failure')
            return atomic(target,value)
        with patch.object(mesh,'atomic',side_effect=fail),self.assertRaises(OSError):runtime.tick()
        self.assertTrue(runtime.failed)
        self.assertEqual(path.read_bytes(),original)
        self.assertFalse(Path(slot['ready_dir']).exists())
        self.assertFalse(Path(slot['signer_dir']).exists())

    def test_ready_lost_signed_response_recovers_with_missing_key_and_exact_head(self):
        runtime=self.open();slot=self.slot();native=runtime.native.call
        def lost(action,*args):
            result=native(action,*args)
            if action=='joint-ready-sign' and '--recover-only' not in args:raise ValueError('injected lost ready response')
            return result
        with patch.object(runtime.native,'call',side_effect=lost),self.assertRaisesRegex(ValueError,'lost ready'):runtime.tick()
        caller=mesh.load(Path(slot['ready_head']),8*1024*1024)
        self.assertIsNotNone(caller['pending'])
        retained=native('joint-ready-status','--ready-dir',slot['ready_dir'])
        self.assertTrue(retained['approved']);self.assertNotEqual(retained['head'],caller['head'])
        Path(slot['key_file']).unlink();self.close()
        restored=self.open();caller=mesh.load(Path(slot['ready_head']),8*1024*1024)
        self.assertEqual(caller['head'],retained['head']);self.assertIsNone(caller['pending']);self.assertIsNone(caller['outbox'])
        self.assertEqual(restored.native.call('joint-ready-status','--ready-dir',slot['ready_dir'])['head'],retained['head'])
        self.assertFalse(Path(slot['signer_dir']).exists())

    def test_changed_pending_ready_purpose_refuses_before_creating_or_adopting(self):
        runtime=self.open();slot=self.slot();native=runtime.native.call
        def interrupted(action,*args):
            if action=='joint-ready-init' and '--observe-only' not in args:raise ValueError('injected before ready creation')
            return native(action,*args)
        with patch.object(runtime.native,'call',side_effect=interrupted),self.assertRaises(ValueError):runtime.tick()
        path=Path(slot['ready_head']);caller=mesh.load(path,8*1024*1024)
        self.assertIsNotNone(caller['initialization']);self.assertFalse(Path(slot['ready_dir']).exists())
        caller['scope']['proposal']['statement']['closing_height']=2
        mesh.atomic(path,caller);before=path.read_bytes();self.close()
        with self.assertRaisesRegex(ValueError,'purpose changed'):self.open()
        self.assertEqual(path.read_bytes(),before)
        self.assertFalse(Path(slot['ready_dir']).exists())

    def activation(self):
        for n in range(4):self.open(n).tick()
        proof=copy.deepcopy(self.scope['proposal'])
        for n in (1,2,3):
            slot=self.c.configs[n]['initial_slot']
            messages=self.c.cli('earth',n,'bft-retained-messages','--signer-dir',slot['signer_dir'])
            proof['old_approvals'].append(next(m['EpochApproval']['approval'] for m in messages if 'EpochApproval' in m))
            status=self.c.cli('earth',n,'joint-ready-status','--ready-dir',self.slot(n)['ready_dir'])
            proof['new_approvals'].append(status['approval']['approval'])
        proof['old_approvals'].sort(key=lambda a:a['key']);proof['new_approvals'].sort(key=lambda a:a['key'])
        path=self.c.file('unit-activation',proof)
        for n in range(5):self.c.cli('earth',n,'install-epoch','--file',path)
        return proof

    def test_new_voter_lost_creation_response_recovers_exact_empty_with_missing_key(self):
        self.activation();runtime=self.runtimes[0];slot=self.slot();native=runtime.native.call
        def lost(action,*args):
            result=native(action,*args)
            if action=='joint-voter-init' and '--observe-only' not in args:raise ValueError('injected lost voter creation')
            return result
        with patch.object(runtime.native,'call',side_effect=lost),self.assertRaisesRegex(ValueError,'lost voter'):runtime.joint.advance()
        path=Path(slot['head_file']);caller=mesh.load(path,8*1024*1024)
        self.assertIsNone(caller['head']);self.assertIsNotNone(caller['initialization'])
        status=native('bft-status','--signer-dir',slot['signer_dir'])
        self.assertEqual(status['records'],0);self.assertEqual(status['head'],caller['initialization']['head'])
        native_bytes=(Path(slot['signer_dir'])/'bft.json').read_bytes()
        Path(slot['key_file']).unlink();self.close()
        restored=self.open();caller=mesh.load(path,8*1024*1024)
        self.assertEqual(caller['head'],status['head']);self.assertIsNone(caller['initialization'])
        self.assertFalse(restored.report(restored.observe(),None,restored.signer_status(),True)['autonomous_signing_enabled'])
        self.assertEqual((Path(slot['signer_dir'])/'bft.json').read_bytes(),native_bytes)

    def test_actual_installed_closing_does_not_block_ordinary_next_era_tick(self):
        self.activation()
        runtime=self.runtimes[0]
        runtime.joint.advance()
        before=runtime.native.call('bft-context')
        self.assertEqual(before['active_epoch_proof']['statement']['number'],1)
        self.assertEqual(runtime.native.call('bft-epoch-proposal')['proposal']['statement'],before['active_epoch_proof']['statement'])
        observed=runtime.tick()
        self.assertEqual(observed['joint_active_slot'],1)
        self.assertTrue(observed['autonomous_signing_enabled'])
        self.assertEqual(runtime.native.call('bft-context')['context']['epoch'],before['context']['epoch'])


if __name__=='__main__':unittest.main()
