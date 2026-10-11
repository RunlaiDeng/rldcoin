"""Fresh no-value Native phase choices, independent policy and delayed keyless finality."""
import copy
import hashlib
import unittest
import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_phase_reference import action_reference
from test_regional_bft_retention import NativeRetentionTests

class NativePhaseScheduleTests(unittest.TestCase):
    setUp=NativeRetentionTests.setUp
    tearDown=NativeRetentionTests.tearDown
    open=NativeRetentionTests.open

    def compare(self,runtime,mode):
        context=runtime.native.call('bft-context')['context'];state=runtime.signer_status()['state']
        number=state['round'] if state['context']==context else 0
        roots=[runtime.native.ledger,runtime.signer,runtime.head_path.parent]
        def inventory():return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for d in roots for p in d.rglob('*') if p.is_file()}
        before=inventory();reference=action_reference(runtime,context,number,mode)
        result=runtime.phase_action(context,number,mode)
        self.assertEqual(wire.canonical(result),wire.canonical(reference));self.assertEqual(inventory(),before)
        return result

    def foreign(self,runtime,index,request):
        message=self.c.sign('earth',index,request)['message']
        runtime.retain(runtime.envelope({'Signed':message}),sync=False)
        return message

    def test_actual_runtime_prepare_commit_then_delayed_certificate_installs_keyless(self):
        runtime=self.open();context=self.native.call('bft-context')['context']
        self.assertEqual(self.compare(runtime,'start'),'Idle')
        runtime.sign({'Propose':dict(round=0,snapshot=runtime.candidate(context),timeout=None)})
        action=self.compare(runtime,'start');proposal=action['Prepare']['proposal']
        for index in (1,2):self.foreign(runtime,index,{'Prepare':proposal})
        self.assertIsNone(self.compare(runtime,'start')['Prepare']['prepared'])
        self.assertEqual(self.compare(runtime,'commit'),'Idle')
        runtime.tick() # The default base profile retains its original one-phase advance.
        commit=self.compare(runtime,'commit')['Commit'];self.assertEqual(len(commit['prepared']['votes']),3)
        runtime.tick();self.assertIsNotNone(runtime.signer_status()['state']['committed'])
        for index in (1,2):self.foreign(runtime,index,{'Commit':dict(proposal=proposal,prepared=commit['prepared'])})
        self.assertIn('Finalize',self.compare(runtime,'start'))
        runtime.sign({'Timeout':dict(context=context,round=0)})
        self.assertIn('Finalize',self.compare(runtime,'finalize'))
        self.assertEqual(self.compare(runtime,'committed'),'Idle')
        records=runtime.signer_status()['records'];runtime.key_file.unlink();runtime.close();self.runtime=None
        runtime=self.open();runtime.tick()
        self.assertEqual(runtime.state['height'],1);self.assertEqual(runtime.signer_status()['records'],records)
        runtime.close();self.runtime=None;runtime=self.open()
        self.assertEqual(self.compare(runtime,'finalize'),'Idle')
        self.assertEqual(runtime.signer_status()['records'],records)

    def test_exact_order_context_and_codec_refusal_preserve_custody(self):
        runtime=self.open();context=self.native.call('bft-context')['context']
        runtime.sign({'Timeout':dict(context=context,round=0)})
        args=('--signer-dir',runtime.signer,'--expected-head',runtime.head['head'],
            '--state-dir',runtime.root,'--expected-state-sha256',runtime._archive_head,
            '--expected-key',runtime.key,'--runtime-format',runtime.format,'--round','1','--mode','start')
        request=dict(context=context,order=list(runtime.state['messages']))
        before=(runtime.state_path.read_bytes(),runtime.head_path.read_bytes(),runtime.signer_status()['records'])
        for changed in (dict(request,order=[]),dict(request,order=request['order']*2),
            dict(request,order=['0'*64]),dict(request,unknown=True),
            dict(request,context=dict(context,parent_height=True)),
            dict(request,context=dict(context,parent_height=1))):
            with self.assertRaises(ValueError):runtime.with_json('bft-phase-action',changed,*args)
        path=self.c.file('duplicate-phase-input',request)
        path.write_bytes(wire.canonical(request)[:-1]+b',"order":[]}')
        with self.assertRaises(ValueError):runtime.native.call('bft-phase-action','--file',path,*args)
        self.assertEqual((runtime.state_path.read_bytes(),runtime.head_path.read_bytes(),runtime.signer_status()['records']),before)
        # A partial or stale independently retained caller observation cannot
        # authorize the new phase interface, even if its archive hash is valid.
        for field in ('pending','outbox'):
            retained=runtime.head;runtime.head=dict(retained,**{field:{'model':'unreleased'}})
            try:
                with self.assertRaises(ValueError):runtime.phase_action(context,1,'start')
            finally:runtime.head=retained

if __name__=='__main__':unittest.main()
