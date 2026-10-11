"""Finite scheduling witnesses only; actual Native tests check authorization."""
import copy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import regional_bft_receive_phase as phase
from regional_bft_node import Runtime,ORIGIN_RUNTIME_FORMAT
from regional_contact_node import Service

def setUpModule():
    global previous_enabled
    previous_enabled=phase.CANDIDATE_ENABLED
    phase.CANDIDATE_ENABLED=True

def tearDownModule():
    phase.CANDIDATE_ENABLED=previous_enabled

class ReceivePhaseTests(unittest.TestCase):
    def runtime(self):
        r=Runtime.__new__(Runtime);r.format=ORIGIN_RUNTIME_FORMAT;r.joint=None
        r.native=SimpleNamespace(currency='1'*64,authority='fixture',ledger=Path('/fixture/native'))
        r.region='2'*64;r.signing_binding=dict(currency=r.native.currency,region=r.region,key='3'*64)
        r.signer=Path('/fixture/signer');r.key=r.signing_binding['key']
        r.head=dict(binding=r.signing_binding,head='4'*64,pending=None,outbox=None)
        r.key_file=Path('/fixture/key');r._receive_phase_operation=object()
        ctx=dict(currency=r.native.currency,region=r.region,epoch='5'*64,previous=None,parent_height=0,parent_block=r.region,parent_state='6'*64)
        status=dict(binding=r.signing_binding,head=r.head['head'],state=None,creation={},records=0,external_rollback_anchor_qualified=False)
        result=dict(format='RLD-BFT-LOOP-ORIGIN-OBSERVATION-V2',native=dict(context=ctx),signer=status,native_history_head='7'*64,signing_authority=False,independent_freshness_qualified=False)
        return r,result
    def test_exact_native_observation_one_use_no_mutable_survivor(self):
        r,v=self.runtime();phase.capture(r,v);v['signer']['head']='changed'
        self.assertEqual(phase.take(r)['signer']['head'],r.head['head']);self.assertIsNone(phase.take(r))
    def test_changed_head_domain_unit_and_pending_discard_before_fallback(self):
        for mode in ('head','authority','ledger','unit','pending','outbox','format','joint'):
            r,v=self.runtime();phase.capture(r,v)
            if mode=='head':r.head['head']='8'*64
            elif mode in ('authority','ledger'):setattr(r.native,mode,'different')
            elif mode=='unit':r._receive_phase_operation=object()
            elif mode in ('pending','outbox'):r.head[mode]={'request':'retained'}
            elif mode=='format':r.format='other'
            else:r.joint=object()
            self.assertIsNone(phase.take(r));self.assertIsNone(r._received_phase_observation)
    def test_changed_configured_signer_identity_or_region_discards_observation(self):
        for field,value in (('signer',Path('/fixture/other-signer')),('key','8'*64),('region','9'*64)):
            with self.subTest(field=field):
                r,v=self.runtime();phase.capture(r,v);setattr(r,field,value)
                self.assertIsNone(phase.take(r))
                self.assertIsNone(r._received_phase_observation)
    def test_invalid_or_oversize_observation_never_captures(self):
        for field,value in (('signing_authority',True),('native_history_head','bad'),('format','other')):
            r,v=self.runtime();v[field]=value
            with self.assertRaises(ValueError):phase.capture(r,v)
            self.assertIsNone(getattr(r,'_received_phase_observation',None))
        r,v=self.runtime()
        with patch.object(phase,'MAX_BYTES',8),self.assertRaises(ValueError):phase.capture(r,v)
    def test_new_service_unit_never_reuses_previous_or_failed_observation(self):
        r,v=self.runtime();r._receive_phase_operation=None
        s=Service.__new__(Service);s.bft=r;tokens=[]
        def body(self):
            tokens.append(r._receive_phase_operation);phase.capture(r,v)
            if len(tokens)==1:raise OSError('interrupted after native return')
            return {'done':True}
        with patch.object(Service,'_tick_service',body):
            with self.assertRaises(OSError):s.tick()
            self.assertIsNone(phase.take(r));self.assertIsNone(r._receive_phase_operation)
            self.assertEqual(s.tick(),{'done':True})
        self.assertIsNot(tokens[0],tokens[1]);self.assertIsNone(phase.take(r))
    def test_cold_restart_and_failed_authentication_cannot_install_phase(self):
        r,v=self.runtime();phase.capture(r,v);cold,_=self.runtime();cold._receive_phase_operation=None
        self.assertIsNone(phase.take(cold));r._received_phase_observation=None
        with self.assertRaises(ValueError):r.receive_many([b'invalid complete frame'])
        self.assertIsNone(phase.take(r))
    def test_last_native_write_invalidates_and_retention_failure_has_no_phase(self):
        r,v=self.runtime();phase.capture(r,v)
        # Full incoming body authentication/sync is an explicit invalidation barrier.
        r.with_json=lambda *a:(_ for _ in ()).throw(ValueError('actual Native refusal'))
        with self.assertRaises(ValueError):r.retain({'format':'other'})
        self.assertIsNone(phase.take(r))
    def test_phase_never_authorizes_signature_or_renews_clock(self):
        r,v=self.runtime();r.entered_at=123.;r._phase_context_started=(b'old',123.)
        phase.capture(r,v);self.assertIsNotNone(phase.take(r))
        self.assertEqual(r.entered_at,123.);self.assertEqual(r._phase_context_started,(b'old',123.))
        self.assertIsNone(r.head['pending']);self.assertIsNone(r.head['outbox'])
    def test_disabled_candidate_keeps_original_service_unit(self):
        r,v=self.runtime();r._receive_phase_operation=None
        s=Service.__new__(Service);s.bft=r
        def original(service):
            self.assertIsNone(r._receive_phase_operation)
            self.assertFalse(phase.enabled(r))
            with self.assertRaises(ValueError):phase.capture(r,v)
            return {'original':True}
        with patch.object(phase,'CANDIDATE_ENABLED',False),patch.object(Service,'_tick_service',original):
            self.assertEqual(s.tick(),{'original':True})


class ComposedAdapterTests(unittest.TestCase):
    def fixture(self):
        from test_regional_bft_live_batch import OriginReceiveBoundaryTests
        base=OriginReceiveBoundaryTests();base.setUp();self.addCleanup(base.temp.cleanup)
        r=base.runtime;r.head=dict(head='a'*64,pending=None,outbox=None)
        r.key='b'*64;r.signer=Path('/fixture/signer');r.signing_binding=dict(currency=base.currency,region=r.region,key=r.key)
        r._receive_phase_operation=object();base.change=None;original=base.call
        def call(action,*args):
            if action=='history-head':return original(action,*args)
            self.assertEqual(action,'bft-origin-network-receive-phase')
            self.assertEqual(args[4:],('--signer-dir',r.signer,'--expected-signer-head',r.head['head'],'--expected-key',r.key))
            result=original('bft-origin-network-receive-batch',*args[:4]);base.calls[-1]=action
            result.update(format='RLD-BFT-ORIGIN-RECEIVE-PHASE-V1',independent_freshness_qualified=False,
                signer=dict(binding=r.signing_binding,head=r.head['head'],state=None,creation={},records=0,external_rollback_anchor_qualified=False))
            return base.change_phase(result) if getattr(base,'change_phase',None) else result
        r.native=SimpleNamespace(call=call,currency=base.currency,authority='fixture',ledger=Path('/fixture/native'))
        return base,r
    def test_complete_receive_and_observation_use_original_two_calls(self):
        from regional_bft_live_batch import receive_observed
        base,r=self.fixture();rows,ctx,observation=receive_observed(r,base.envelopes)
        self.assertEqual(base.calls,['history-head','bft-origin-network-receive-phase']);self.assertEqual(len(rows),4)
        self.assertEqual(observation['native']['context'],ctx);self.assertEqual(list(r.root.iterdir()),[])
    def test_mutation_refusal_or_changed_signed_response_never_falls_back(self):
        from regional_bft_live_batch import receive_observed
        for mode in ('native','head','binding','flags','capacity'):
            base,r=self.fixture()
            def change(v):
                if mode=='native':raise ValueError('postreceive observation refused')
                if mode=='head':v['signer']['head']='c'*64
                elif mode=='binding':v['signer']['binding']={}
                elif mode=='flags':v['independent_freshness_qualified']=True
                else:v['pad']='x'*(8*1024*1024)
                return v
            base.change_phase=change
            with self.assertRaises(ValueError):receive_observed(r,base.envelopes)
            self.assertEqual(base.calls,['history-head','bft-origin-network-receive-phase']);self.assertEqual(list(r.root.iterdir()),[])
            self.assertIsNone(phase.take(r))
    def test_retention_must_finish_before_phase_capture_and_failures_leave_no_witness(self):
        from regional_bft_observation import Observation
        import interstellar_transfer as wire
        import interstellar_mesh as mesh
        for fail in (False,True):
            base,r=self.fixture();r.state={'messages':{}};r.observation=Observation();retained=[]
            r._observe_context=lambda ctx:None
            def keep(envelope,checked,sync):
                self.assertFalse(sync);self.assertIsNone(phase.take(r));retained.append(envelope)
                if fail and len(retained)==2:raise OSError('durable companion retention failed')
            r._retain_checked=keep
            raws=[wire.make_frame('regional-bft',r.region,r.region,mesh.digest(e),wire.canonical(e)) for e in base.envelopes]
            if fail:
                with self.assertRaises(OSError):Runtime.receive_many(r,raws)
                self.assertIsNone(phase.take(r))
            else:
                Runtime.receive_many(r,raws);self.assertEqual(retained,base.envelopes)
                self.assertEqual(phase.take(r)['signer']['head'],r.head['head'])

if __name__ == "__main__":
    unittest.main()
