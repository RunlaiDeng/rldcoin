"""Fresh public-key no-value Native tick policy and nonmutating clock checks."""
import copy
import hashlib
import time
import unittest
from regional_bft_tick_reference import plan_reference
from regional_bft_tick_schedule import request
from test_regional_native_phase_schedule import NativePhaseScheduleTests
import interstellar_transfer as wire

class NativeTickScheduleTests(NativePhaseScheduleTests):
    # Parent tests are loaded separately; this class only adds tick observations.
    test_actual_runtime_prepare_commit_then_delayed_certificate_installs_keyless=None
    test_exact_order_context_and_codec_refusal_preserve_custody=None

    def compare_plan(self,runtime,stage='begin',stopped=False,proposed=None):
        context=runtime.native.call('bft-context')['context'];state=runtime.signer_status()['state']
        number=state['round'] if state['context']==context else 0
        roots=[runtime.native.ledger,runtime.signer,runtime.head_path.parent,runtime.root]
        def inventory():return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for d in roots for p in d.rglob('*') if p.is_file()}
        before=inventory();calls=[];original=runtime.with_json
        def call(*args):
            result=original(*args)
            if args[0]=='bft-tick-observation':calls.append(result)
            return result
        runtime.with_json=call;early=time.monotonic()
        try:actual=runtime.tick_plan(context,number,stage,stopped,proposed)
        finally:runtime.with_json=original
        late=time.monotonic();self.assertEqual(len(calls),1)
        now=calls[0]['monotonic_now'];self.assertGreaterEqual(now,early);self.assertLessEqual(now,late)
        expected=plan_reference(runtime,context,number,stage,now,stopped,proposed,state)
        self.assertEqual(wire.canonical(actual),wire.canonical(expected));self.assertEqual(inventory(),before)
        return actual

    def test_same_os_clock_original_entry_phase_priority_and_timeout(self):
        runtime=self.open();context=runtime.native.call('bft-context')['context']
        runtime._initial_proposal_wait_used=False;runtime._timeout_refresh_used=False
        runtime.entered_at=time.monotonic();runtime.block_interval=3600
        self.assertEqual(self.compare_plan(runtime),{'Phase':'Idle'})
        runtime.entered_at=time.monotonic()-3601
        self.assertIn('Propose',self.compare_plan(runtime))
        runtime.sign({'Propose':dict(round=0,snapshot=runtime.candidate(context),timeout=None)})
        runtime.entered_at=time.monotonic()-3601
        chosen=self.compare_plan(runtime);self.assertIn('Prepare',chosen['Phase'])
        runtime.sign({'Prepare':chosen['Phase']['Prepare']['proposal']})
        self.assertEqual(self.compare_plan(runtime,'commit'),{'Phase':'Idle'})
        runtime.entered_at=time.monotonic()-3601
        self.assertIn('Timeout',self.compare_plan(runtime))
        self.assertEqual(self.compare_plan(runtime,stopped=True),{'Phase':'Idle'})

    def test_typed_stage_clock_order_and_partial_caller_refuse_without_custody(self):
        runtime=self.open();context=runtime.native.call('bft-context')['context']
        runtime.entered_at=time.monotonic();runtime._initial_proposal_wait_used=False;runtime._timeout_refresh_used=False
        args=('--signer-dir',runtime.signer,'--expected-head',runtime.head['head'],
            '--state-dir',runtime.root,'--expected-state-sha256',runtime._archive_head,
            '--expected-key',runtime.key,'--runtime-format',runtime.format,'--round','0')
        payload=request(runtime,context,'begin',False,None)
        before=(runtime.state_path.read_bytes(),runtime.head_path.read_bytes(),runtime.signer_status()['records'])
        for field,value in [('stage','unknown'),('stage','after-proposal'),('entered_at',-1.),
            ('entered_at',time.monotonic()+3600),('entered_at',True),('interval',0.49),('interval',1),
            ('timeout',1.99),('stopped',1),('initial_wait',1),('order',['0'*64]),('unknown',True)]:
            bad=copy.deepcopy(payload);bad[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):runtime.with_json('bft-tick-observation',bad,*args)
        for field in ('pending','outbox'):
            retained=runtime.head;runtime.head=dict(retained,**{field:{'unreleased':True}})
            try:
                with self.assertRaises(ValueError):runtime.tick_plan(context,0,'begin')
            finally:runtime.head=retained
        self.assertEqual((runtime.state_path.read_bytes(),runtime.head_path.read_bytes(),runtime.signer_status()['records']),before)

if __name__=='__main__':unittest.main()
