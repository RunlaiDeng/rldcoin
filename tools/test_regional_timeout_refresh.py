"""Timeout boundary scheduling models plus actual mesh custody.

Models exercise exact public methods; they grant no Native signing authority.
The separately source-bound real CLI counter verifies actual signatures/heads.
"""
from contextlib import nullcontext
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import bft_tick_fixture as baseline
import interstellar_mesh as mesh
from regional_bft_node import ORIGIN_RUNTIME_FORMAT
from regional_contact_node import MAX_PER_TICK
from test_interstellar_mesh import Fixture as MeshFixture
import test_regional_contact_receive_ring as ring
from test_regional_contact_receive_ring import ident
import test_regional_contact_receive_trace as trace_tests


class TimeoutRefreshTests(unittest.TestCase):
    def runtime(self):
        f=baseline.Fixture();f.format=ORIGIN_RUNTIME_FORMAT;f.joint=None
        f.loop_observation=lambda:(f.observe(),f.signer_status())
        baseline.clock.now=22
        return f

    def test_empty_or_slow_refresh_runs_once_without_renewal(self):
        for mode in ('empty','slow'):
            with self.subTest(mode=mode):
                f=self.runtime();calls=[];operations=[]
                def refresh():
                    calls.append(mode);operations.append(f._tick_operation)
                    if mode=='slow':baseline.clock.now=23
                    f._composed_phase_observation=('stale',);f._sign_native_head='stale'
                    return True
                f.before_timeout=refresh
                sign=f.sign
                def checked_sign(request):
                    self.assertIsNot(f._tick_operation,operations[0])
                    self.assertIsNone(f._composed_phase_observation)
                    self.assertIsNone(f._sign_native_head)
                    self.assertEqual(f.entered_at,0)
                    sign(request)
                f.sign=checked_sign
                f.tick()
                self.assertEqual(calls,[mode])
                self.assertEqual(f.requests,[dict(kind='Timeout',round=0)])
                self.assertEqual(f.counts['bft-context'],2)

    def test_late_proposal_takes_prepare_before_expired_timeout(self):
        f=self.runtime();calls=[]
        def refresh():calls.append(True);f.proposal(0);return True
        f.before_timeout=refresh;f.tick()
        self.assertEqual(calls,[True])
        self.assertEqual(f.requests,[dict(kind='Prepare',round=0)])

    def test_native_phase_advancement_is_reobserved_before_request(self):
        f=self.runtime()
        def refresh():f.native_state['round']=1;return True
        f.before_timeout=refresh;f.tick()
        self.assertEqual(f.requests,[])
        self.assertEqual(f.slot[1],1)
        self.assertEqual(f.entered_at,22) # actual new slot, not input renewal.

    def test_full_quota_does_not_reobserve_or_add_an_attempt(self):
        f=self.runtime();f.before_timeout=lambda:False;f.tick()
        self.assertEqual(f.counts['bft-context'],1)
        self.assertEqual(f.requests,[dict(kind='Timeout',round=0)])

    def test_failed_refresh_never_signs_using_old_observation(self):
        f=self.runtime()
        def refresh():raise ValueError('authentication/persistence unavailable')
        f.before_timeout=refresh
        with self.assertRaises(ValueError):f.tick()
        self.assertEqual(f.requests,[])
        self.assertIsNone(f._tick_operation)

    def test_other_profiles_and_standalone_runtime_keep_original_behavior(self):
        f=self.runtime();f.format='other';f.before_timeout=lambda:(_ for _ in ()).throw(AssertionError())
        f.tick();self.assertEqual(f.requests,[dict(kind='Timeout',round=0)])
        f=self.runtime();f.tick();self.assertEqual(f.counts['bft-context'],1)

    def test_operation_quota_counts_failed_selections_and_late_class_fairness(self):
        fixture=ring.ReceiveRingTests();s,rows,receipts=fixture.setup_ring(novel=(1,),background=(100,))
        q={'attempted':set(),'novel':0,'background':0}
        first=s.receive_candidates(rows,receipts,ident(777),q)
        self.assertEqual(first,[ident(1),ident(100)])
        # Both fail authentication: no seen hint; nevertheless no same-unit retry.
        for n in (2,3,4,101,102):
            rows[ident(n)]=dict(rows[ident(1 if n<100 else 100)],export_id=ident(n if n<100 else 999))
            receipts[ident(n)]=True
        late=s.receive_candidates(rows,receipts,ident(777),q)
        self.assertEqual(late,[ident(2),ident(101)])
        for _ in range(100):
            self.assertEqual(s.receive_candidates(rows,receipts,ident(777),q),[])
        self.assertEqual(len(q['attempted']),MAX_PER_TICK)
        self.assertEqual((q['novel'],q['background']),(2,2))

    def test_single_class_borrows_only_unused_places_and_next_unit_serves_other(self):
        fixture=ring.ReceiveRingTests();s,rows,receipts=fixture.setup_ring(novel=(1,2,3),background=())
        q={'attempted':set(),'novel':0,'background':0}
        self.assertEqual(len(s.receive_candidates(rows,receipts,ident(777),q)),3)
        for n in (100,101):rows[ident(n)]=dict(rows[ident(1)],export_id=ident(999));receipts[ident(n)]=True
        self.assertEqual(s.receive_candidates(rows,receipts,ident(777),q),[ident(100)])
        new={'attempted':set(),'novel':0,'background':0}
        chosen=s.receive_candidates(rows,receipts,ident(777),new)
        self.assertEqual(len(chosen),4);self.assertEqual(new['background'],2)

    def test_service_late_receive_uses_full_validation_and_restores_callback(self):
        for mode in ('success','native-refused','bad-receipt','full'):
            with self.subTest(mode=mode):
                s,trace,receive,packet,raw=trace_tests.ReceiveTraceTests().service('native-refused' if mode=='native-refused' else 'success')
                s.bft.format=ORIGIN_RUNTIME_FORMAT;s.bft.joint=None
                before=object();s.bft.before_timeout=before
                rows={packet:dict(destination='c'*64,kind='regional-bft',export_id='d'*64)}
                if mode=='full':rows={ident(n):dict(rows[packet]) for n in range(1,5)}
                node=SimpleNamespace(id='c'*64,network='a'*64,state={'adverts':{}},tick=lambda **_:dict(errors=[]),
                    summaries=lambda:rows if mode=='full' else {},receipts=lambda:{i:{} for i in rows},transit=lambda i:{})
                drains=[]
                def drain():drains.append(True);node.summaries=lambda:rows;return []
                node.drain_spool_incoming=drain
                s.selection_node=lambda:nullcontext(node)
                decisions=[]
                s.bft.tick=lambda:decisions.append(s.bft.before_timeout()) or {}
                with patch('regional_contact_node.mesh.transit_check',return_value=({},raw,[])), \
                     patch('regional_contact_node.mesh.receipt_matches',side_effect=ValueError('bad receipt') if mode=='bad-receipt' else None), \
                     patch('regional_contact_node.mesh.atomic'):
                    report=s.tick()
                self.assertIs(s.bft.before_timeout,before)
                self.assertEqual(s.progress['cursor'],4)
                if mode=='full':self.assertEqual(drains,[]);self.assertEqual(decisions,[False]);self.assertEqual(receive.call_count,1)
                else:
                    self.assertEqual(drains,[True]);self.assertEqual(decisions,[True])
                    if mode=='bad-receipt':receive.assert_not_called()
                    else:receive.assert_called_once_with([raw])
                if mode=='native-refused':self.assertNotIn(packet,s.bft_seen);self.assertTrue(report['deferred'])

    def test_intake_only_preserves_cursor_and_outgoing_and_cold_custody(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture=MeshFixture(directory);fixture.rounds()
            peer=fixture.identities['proxima']['node_id']
            with fixture.node('earth') as sender:
                packet=sender.enqueue(fixture.frame(),peer);self.assertEqual(sender.flush_spool_outgoing(),[])
            with fixture.node('proxima') as node:
                cursor=node.state['cursor'];outgoing={str(p):p.read_bytes() for c in node.contacts.values() for p in c['outbox'].glob('*.json')}
                with patch.object(node,'archive_completed',side_effect=AssertionError('extra archive')):
                    self.assertEqual(node.drain_spool_incoming(),[])
                self.assertEqual(node.state['cursor'],cursor)
                self.assertEqual(outgoing,{str(p):p.read_bytes() for c in node.contacts.values() for p in c['outbox'].glob('*.json')})
                self.assertIn(packet,node.receipts())
            with fixture.node('proxima') as cold:self.assertIn(packet,cold.receipts())


if __name__=='__main__':unittest.main()
