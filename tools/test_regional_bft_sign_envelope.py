"""Custody-order and binding models only; no Native proof/signing authority."""
import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import interstellar_transfer as wire
from regional_bft_node import Runtime,ORIGIN_RUNTIME_FORMAT
from regional_bft_sign_envelope import FORMAT


class Fixture:
    _sign=Runtime._sign
    _sign_stage=Runtime._sign_stage
    phase_status=Runtime.phase_status
    reconcile=Runtime.reconcile
    def __init__(self,fail=None,alter=None):
        self.format=ORIGIN_RUNTIME_FORMAT;self.joint=None
        self.signer=Path('/model-signer');self.key_file=Path('/model-key')
        self.key='2'*64;self.region='3'*64
        self.native=SimpleNamespace(currency='4'*64,authority='5'*64,ledger=Path('/model-ledger'))
        self.signing_binding=dict(currency=self.native.currency,region=self.region,key=self.key)
        self.head=dict(binding=copy.deepcopy(self.signing_binding),head='a'*64,pending=None,outbox=None)
        self.request={'Timeout':{'model_only':True}};self.order=[];self.fail=fail;self.alter=alter
        self._tick_operation=object();self._sign_native_head='c'*64
        self.native_head='a'*64;self.entered_at=-1;self.retained=0;self.fresh_reads=0
        self.message={'Timeout':{'model_native_response':True}}
    def save_head(self,value):
        stage='pending' if value['pending'] else 'response' if value['outbox'] else 'clear'
        self.order.append(stage)
        if self.fail==stage:raise OSError('injected '+stage)
        self.head=copy.deepcopy(value)
    def with_json(self,action,request,*args):
        self.order.append(action)
        if action=='bft-sign':
            assert '--recover-only' in args
            if self.native_head=='a'*64:raise ValueError('recovery cannot first-sign')
            return dict(message=self.message,head=self.native_head,previous_head='a'*64,recovered_exact_retry=True)
        assert action=='bft-sign-local-envelope';assert self.head['pending']==self.request
        assert args==('--signer-dir',self.signer,'--expected-head','a'*64,
                      '--expected-native-head','c'*64,'--expected-key',self.key,'--key-file',self.key_file)
        self.native_head='b'*64
        if self.fail=='native-loss':raise OSError('native response lost')
        signed=dict(message=copy.deepcopy(self.message),head=self.native_head,previous_head='a'*64,recovered_exact_retry=False)
        result=dict(format=FORMAT,currency=self.native.currency,region=self.region,
            request_sha256=hashlib.sha256(wire.canonical(request)).hexdigest(),native_history_head='c'*64,
            signed=signed,status=dict(binding=copy.deepcopy(self.signing_binding),creation={},head='b'*64,
                state=dict(round=0),records=1,external_rollback_anchor_qualified=False),
            envelope=dict(format='RLD-REGIONAL-BFT-ORIGIN-NETWORK-V3',currency=self.native.currency,
                region=self.region,body={'Signed':copy.deepcopy(self.message)},origins=[],evidence={}),
            checked=dict(message_id='d'*64,value=None,evidence=dict(snapshots=[]),epochs=[]),
            signature_retained=True,carriage_released=False,ledger_changed=False,independent_freshness_qualified=False)
        if self.alter:self.alter(result)
        return result
    def _retain_checked(self,envelope,checked,sync,local):
        assert self.head['head']=='b'*64 and self.head['pending'] is None and self.head['outbox']==self.message
        assert sync is False and local is True
        self.order.append('retain')
        if self.fail=='retain':raise OSError('retention failed')
        self.retained+=1
    def signer_status(self):
        self.fresh_reads+=1
        if self.native_head!=self.head['head']:raise ValueError('independent caller differs from native head')
        return dict(head=self.native_head,binding=self.signing_binding,state=None)
    def run(self):
        with patch('regional_bft_node.private',return_value=self.key_file):self._sign(self.request)


class ComposedSignTests(unittest.TestCase):
    def test_caller_head_is_durable_before_retention_and_only_one_native_call(self):
        f=Fixture();f.run()
        self.assertEqual(f.order,['pending','bft-sign-local-envelope','response','retain','clear'])
        self.assertEqual(f.retained,1);self.assertEqual(f.head['head'],'b'*64)
        self.assertIsNone(f.head['pending']);self.assertIsNone(f.head['outbox'])
        self.assertEqual(f.phase_status()['head'],'b'*64);self.assertEqual(f.fresh_reads,0)
    def test_response_loss_never_falls_back_or_first_signs_on_recovery(self):
        f=Fixture(fail='native-loss')
        with self.assertRaises(OSError):f.run()
        self.assertEqual(f.native_head,'b'*64);self.assertEqual(f.head['head'],'a'*64)
        self.assertEqual(f.head['pending'],f.request);self.assertEqual(f.retained,0)
        f.reconcile();self.assertEqual(f.head['head'],'b'*64);self.assertEqual(f.head['outbox'],f.message)
        self.assertEqual(f.order.count('bft-sign-local-envelope'),1)
    def test_pending_write_failure_never_invokes_native_and_unsigned_recovery_clears_only_pending(self):
        f=Fixture(fail='pending')
        with self.assertRaises(OSError):f.run()
        self.assertEqual(f.order,['pending']);self.assertEqual(f.native_head,'a'*64)
        f=Fixture();f.head['pending']=f.request;f.reconcile()
        self.assertEqual(f.native_head,'a'*64);self.assertIsNone(f.head['pending']);self.assertEqual(f.retained,0)
    def test_failed_head_or_retention_preserves_exact_pending_or_outbox(self):
        for failure in ['response','retain','clear']:
            f=Fixture(fail=failure)
            with self.assertRaises(OSError):f.run()
            if failure=='response':
                self.assertEqual(f.head['head'],'a'*64);self.assertEqual(f.head['pending'],f.request)
            else:
                self.assertEqual(f.head['head'],'b'*64);self.assertEqual(f.head['outbox'],f.message)
            self.assertFalse(hasattr(f,'_composed_phase_observation'))
    def test_response_bindings_or_altered_complete_body_refuse_without_caller_release(self):
        changes=[lambda x:x.update(native_history_head='f'*64),lambda x:x.update(request_sha256='f'*64),
            lambda x:x['status'].update(head='a'*64),lambda x:x['status']['binding'].update(key='f'*64),
            lambda x:x['envelope']['body'].update(Signed={'Timeout':{'altered':True}}),
            lambda x:x.update(carriage_released=True),lambda x:x.update(ledger_changed=True),
            lambda x:x.update(independent_freshness_qualified=True)]
        for changed in changes:
            f=Fixture(alter=changed)
            with self.assertRaises(ValueError):f.run()
            self.assertEqual(f.head['head'],'a'*64);self.assertEqual(f.head['pending'],f.request)
            self.assertEqual(f.retained,0)
    def test_phase_observation_is_immutable_and_refuses_other_tick_head_native_and_pending(self):
        f=Fixture();f.run();s=f.phase_status();s['head']='mutated';self.assertEqual(f.phase_status()['head'],'b'*64)
        for changed in ['tick','head','native','pending']:
            f=Fixture();f.run()
            if changed=='tick':f._tick_operation=object()
            elif changed=='head':f.head['head']='e'*64
            elif changed=='native':f.native.ledger=Path('/other-model-ledger')
            else:f.head['pending']=f.request
            try:f.phase_status()
            except ValueError:pass
            self.assertEqual(f.fresh_reads,1)
    def test_tick_finally_discards_all_sign_observations_even_on_failure(self):
        f=Fixture();f.observation=None
        def step():
            f._composed_phase_observation=('model',b'bytes',b'bytes')
            f._sign_native_head='a'*64
            raise ValueError('tick failed')
        f._tick=step
        with self.assertRaises(ValueError):Runtime.tick(f)
        self.assertIsNone(f._tick_operation);self.assertIsNone(f._composed_phase_observation)
        self.assertIsNone(f._sign_native_head)


if __name__=='__main__':unittest.main()
