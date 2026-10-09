"""Exact Service wait/intake models; synthetic responses grant no authority."""
from contextlib import nullcontext
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import regional_contact_node as contact
from regional_bft_node import ORIGIN_RUNTIME_FORMAT,FORMAT
from test_regional_contact_receive_trace import ReceiveTraceTests
from test_regional_contact_receive_ring import ident


class InitialProposalIntakeTests(unittest.TestCase):
    def run_service(self,mode='success'):
        s,trace,receive,packet,raw=ReceiveTraceTests().service('native-refused' if mode=='native-refused' else 'success')
        s.bft.format=FORMAT if mode=='legacy' else ORIGIN_RUNTIME_FORMAT;s.bft.joint=None
        original=lambda due:False;s.bft.before_initial_proposal=original
        rows={packet:dict(destination='c'*64,kind='regional-bft',export_id='d'*64)}
        if mode=='full':rows={ident(n):dict(rows[packet]) for n in range(1,5)}
        now=[1.5];drains=[];phases=[];arrived=[False]
        node=SimpleNamespace(id='c'*64,network='a'*64,state={'adverts':{}},tick=lambda **_:dict(errors=[]),
            summaries=lambda:rows if mode=='full' else {},receipts=lambda:{i:{} for i in rows},transit=lambda i:{})
        def drain():
            drains.append(now[0]);node.summaries=lambda:rows if arrived[0] else {};return []
        node.drain_spool_incoming=drain;s.selection_node=lambda:nullcontext(node)
        def sleep(seconds):now[0]+=seconds;arrived[0]=now[0]>=1.75
        def tick():
            s.bft.before_initial_proposal(2.)
            phases.append(('candidate',now[0],receive.call_count))
            return {}
        s.bft.tick=tick
        with patch.object(contact.time,'monotonic',side_effect=lambda:now[0]),patch.object(contact.time,'sleep',side_effect=sleep), \
             patch.object(contact.mesh,'transit_check',return_value=({},raw,[])), \
             patch.object(contact.mesh,'receipt_matches',side_effect=ValueError('bad receipt') if mode=='bad-receipt' else None), \
             patch.object(contact.mesh,'atomic'):
            report=s.tick()
        self.assertIs(s.bft.before_initial_proposal,original)
        self.assertEqual(s.progress['cursor'],4)
        return s,receive,packet,raw,drains,phases,report

    def test_submission_arriving_during_existing_wait_reaches_native_before_candidate(self):
        s,receive,packet,raw,drains,phases,_=self.run_service()
        receive.assert_called_once_with([raw]);self.assertIn(packet,s.bft_seen)
        self.assertEqual(len(drains),1);self.assertGreaterEqual(drains[0],2.)
        self.assertEqual(phases[0][2],1)

    def test_refused_authentication_bad_receipt_full_quota_and_legacy_remain_distinct(self):
        for mode in ('native-refused','bad-receipt','full','legacy'):
            with self.subTest(mode=mode):
                s,receive,packet,raw,drains,phases,report=self.run_service(mode)
                if mode=='native-refused':receive.assert_called_once_with([raw]);self.assertNotIn(packet,s.bft_seen);self.assertTrue(report['deferred'])
                elif mode=='bad-receipt':receive.assert_not_called();self.assertTrue(report['rejected'])
                elif mode=='full':self.assertEqual(drains,[]);self.assertEqual(receive.call_count,1)
                else:receive.assert_not_called();self.assertEqual(drains,[]);self.assertEqual(phases[0][1],1.5)

    def test_wait_refresh_refusal_stops_release_without_renewing_due(self):
        s=contact.Service.__new__(contact.Service);s.tcp=SimpleNamespace(running=True);now=[1.5];calls=[]
        def sleep(seconds):now[0]+=seconds
        def refusal():calls.append(now[0]);raise ValueError('full authentication unavailable')
        with patch.object(contact.time,'monotonic',side_effect=lambda:now[0]),patch.object(contact.time,'sleep',side_effect=sleep):
            with self.assertRaisesRegex(ValueError,'full authentication unavailable'):s.wait_initial_proposal(2.,refusal)
        self.assertEqual(len(calls),1);self.assertAlmostEqual(now[0],2.)

    def test_out_of_bound_or_stopping_wait_cannot_take_intake(self):
        s=contact.Service.__new__(contact.Service);s.tcp=SimpleNamespace(running=False);calls=[]
        with patch.object(contact.time,'monotonic',return_value=1.):
            self.assertFalse(s.wait_initial_proposal(2.1,lambda:calls.append(True)))
            with self.assertRaises(contact.tcp.MeshRuntimeStopping):s.wait_initial_proposal(1.5,lambda:calls.append(True))
        self.assertEqual(calls,[])


if __name__=='__main__':unittest.main()
