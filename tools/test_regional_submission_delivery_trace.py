"""Exact delivery boundaries and refusal tests; no ledger qualification."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_contact_trace import ContactTrace,TraceCursor,MAX_EVENTS
from regional_contact_trace_shards import verify_shards
from regional_submission_trace import SubmissionTrace,SubmissionCursor,verify_submission_shards
from regional_submission_delivery_trace import DeliveryTrace,DeliveryCursor,DeliveryShards,verify_delivery_shards,candidate_event
from regional_bft_node import Runtime
from regional_contact_node import NativeRefusal


class DeliveryTraceTests(unittest.TestCase):
    def trace(self):
        t=DeliveryTrace();t.bind('a'*64,'b'*64);return t

    def test_received_bound_then_candidate_scan_preserves_exact_complete_envelope(self):
        t=self.trace();envelope={'format':'RLD-REGIONAL-BFT-NETWORK-V2','currency':'a'*64,'region':'c'*64,'evidence':{'snapshots':[]},'body':{'Submission':[]}};payload=wire.canonical(envelope);eid=mesh.digest(envelope);raw=wire.make_frame('regional-bft','c'*64,'c'*64,eid,payload)
        for stage in ('native_receive_selected','native_receive_attempt'):t.native_stage(stage,'d'*64,raw)
        t.event('native_validation_bound',envelope_id=eid)
        t.native_received('d'*64,raw)
        r=SimpleNamespace(contact_trace=t,state={'messages':SimpleNamespace(content=lambda i:eid)})
        context={'parent_height':3};candidate_event(r,'candidate_submission_seen',context,ident='retained')
        rows=t.snapshot()['events'];self.assertEqual([r['envelope_id'] for r in rows],[eid]*5)
        self.assertEqual(rows[-1]['selected'],3);self.assertEqual(rows[-1]['scope_id'],mesh.digest(context))
        self.assertTrue(DeliveryCursor('a'*64,'b'*64).drain(t.snapshot())['this_interval_complete'])
        with self.assertRaises(ValueError):SubmissionCursor('a'*64,'b'*64).drain(t.snapshot())
        with self.assertRaises(ValueError):TraceCursor('a'*64,'b'*64).drain(t.snapshot())

    def test_burst_gaps_refusals_restart_and_other_profile_are_never_coverage(self):
        t=self.trace()
        for _ in range(MAX_EVENTS+15):t.event('prepare_start')
        t.event('native_receive_refused',envelope_id='c'*64,error_class='ValueError')
        d=DeliveryCursor('a'*64,'b'*64).drain(t.snapshot());self.assertTrue(d['this_interval_complete']);self.assertFalse(d['complete_transport_trace'])
        c=DeliveryCursor('a'*64,'b'*64);c.drain(t.snapshot())
        with self.assertRaises(ValueError):c.drain(self.trace().snapshot())
        for _ in range(MAX_EVENTS+1):t.event('native_validation_bound',envelope_id='c'*64)
        self.assertFalse(c.drain(t.snapshot())['this_interval_complete'])
        v=SubmissionTrace();v.bind('a'*64,'b'*64)
        with self.assertRaises(ValueError):DeliveryCursor('a'*64,'b'*64).drain(v.snapshot())
        t=self.trace();t.event('candidate_command_selected',command_id='bad')
        self.assertFalse(DeliveryCursor('a'*64,'b'*64).drain(t.snapshot())['this_interval_complete'])

    def test_four_cold_profile_pid_and_corruption_refuse(self):
        with tempfile.TemporaryDirectory() as folder:
            slots={i:(100+i,format(i+1,'064x')) for i in range(4)};j=DeliveryShards('a'*64,slots,deadline=10,path=Path(folder)/'delivery')
            for i in range(4):
                t=self.trace();t.binding=('a'*64,slots[i][1]);t.event('native_validation_bound',envelope_id='c'*64)
                j.sample(i,dict(process_id=slots[i][0],contact_trace=t.snapshot()),now=1)
            j.close();s=j.snapshot();self.assertEqual(verify_delivery_shards(j.path,s,network='a'*64,slots=slots)['events'],4)
            for verify in (verify_shards,verify_submission_shards):
                with self.assertRaises(ValueError):verify(j.path,s,network='a'*64,slots=slots)
            with self.assertRaises(ValueError):verify_delivery_shards(j.path,s,network='a'*64,slots={**slots,0:(999,slots[0][1])})
            p=j.path/'part-00.jsonl';p.write_bytes(p.read_bytes()+b' ')
            with self.assertRaises(ValueError):verify_delivery_shards(j.path,s,network='a'*64,slots=slots)

    def runtime(self,trace,commands):
        r=Runtime.__new__(Runtime);r.contact_trace=trace;r.joint=None;r.miner='test';r.calls=[]
        class Messages:
            def bodies(self):return [('retained',{'Submission':commands},None,False)]
            def content(self,ident):return 'c'*64
        r.state={'messages':Messages()};r.native=SimpleNamespace(call=lambda action:[])
        def call(action,rows,*args):
            r.calls.append((action,list(rows),args))
            return {'selected':list(rows)}
        r.with_json=call;return r

    def test_candidate_exact_command_order_cap_duplicate_and_invalid_trial(self):
        commands=[{'command':i} for i in range(6)];commands.insert(1,commands[0]);t=self.trace();r=self.runtime(t,commands)
        expected=commands[0:1]+commands[2:5]
        self.assertEqual(r.candidate({'parent_height':3}),{'selected':expected})
        self.assertEqual([len(v[1]) for v in r.calls],[1,2,3,4,4])
        rows=t.snapshot()['events'];self.assertEqual(rows[0]['stage'],'candidate_selection_started');self.assertEqual(rows[1]['stage'],'candidate_submission_seen')
        self.assertEqual([v['command_id'] for v in rows if v['stage']=='candidate_command_selected'],list(map(mesh.digest,expected)))
        self.assertEqual(sum(v['stage']=='candidate_command_attempted' for v in rows),4)

    def test_candidate_refusal_and_busy_keep_original_behavior_without_fallback(self):
        command={'command':1}
        for busy in (False,True):
            with self.subTest(busy=busy):
                t=self.trace();r=self.runtime(t,[command]);calls=[]
                def call(action,rows,*args):
                    calls.append(list(rows))
                    if rows:
                        if busy:raise NativeRefusal('bft-candidate',1,'regional candidate rejected: complete stream already locked')
                        raise ValueError('original invalid command')
                    return {'selected':[]}
                r.with_json=call
                if busy:
                    with self.assertRaises(NativeRefusal):r.candidate({'parent_height':3})
                    self.assertEqual(calls,[[command]])
                else:self.assertEqual(r.candidate({'parent_height':3}),{'selected':[]});self.assertEqual(calls,[[command],[]])
                stages=[v['stage'] for v in t.snapshot()['events']];self.assertIn('candidate_command_refused',stages);self.assertNotIn('candidate_command_selected',stages)

    def test_diagnostic_failure_or_v1_does_not_change_candidate_or_high_lock(self):
        for trace in (None,SubmissionTrace(),self.trace()):
            r=self.runtime(trace,[{'command':1}])
            if isinstance(trace,DeliveryTrace):trace.event=lambda *a,**k:(_ for _ in ()).throw(OSError('diagnostic'))
            self.assertEqual(r.candidate({'parent_height':3}),{'selected':[{'command':1}]});self.assertEqual(len(r.calls),2)
            with self.assertRaisesRegex(ValueError,'highest prepared'):r.candidate({'parent_height':3},'d'*64)
            if trace is not None and not isinstance(trace,DeliveryTrace):self.assertEqual(trace.sequence,0)


if __name__=='__main__':unittest.main()
