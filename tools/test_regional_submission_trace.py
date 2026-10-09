"""Narrow diagnostics only; no Native/signing/network/value qualification."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_contact_trace import ContactTrace,TraceCursor,MAX_EVENTS
from regional_contact_trace_shards import verify_shards
from regional_contact_node import Native
from regional_submission_trace import SubmissionTrace,SubmissionCursor,SubmissionShards,verify_submission_shards,FORMAT


class SubmissionTraceTests(unittest.TestCase):
    def trace(self):
        t=SubmissionTrace();t.bind('a'*64,'b'*64);return t

    def test_explicit_subset_preserves_all_selected_rows_under_full_transport_burst(self):
        t=self.trace();full=ContactTrace();full.bind('a'*64,'b'*64)
        for _ in range(MAX_EVENTS+15):
            t.event('prepare_start');full.event('prepare_start')
        for stage in ('submission_input_read','submission_auth_started','submission_retained'):
            t.event(stage,envelope_id='c'*64)
        value=t.snapshot();self.assertEqual(value['format'],FORMAT)
        self.assertEqual(value['sequence'],3);self.assertEqual(value['evicted_events'],0)
        delta=SubmissionCursor('a'*64,'b'*64).drain(value)
        self.assertTrue(delta['this_interval_complete']);self.assertFalse(delta['complete_transport_trace'])
        self.assertEqual(len(delta['events']),3)
        with self.assertRaises(ValueError):TraceCursor('a'*64,'b'*64).drain(value)
        with self.assertRaises(ValueError):SubmissionCursor('a'*64,'b'*64).drain(full.snapshot())
        self.assertFalse(TraceCursor('a'*64,'b'*64).drain(full.snapshot())['this_interval_complete'])

    def test_selected_gap_rejection_restart_or_injected_stage_never_passes(self):
        t=self.trace()
        for _ in range(MAX_EVENTS+1):t.event('consensus_tick_started')
        self.assertFalse(SubmissionCursor('a'*64,'b'*64).drain(t.snapshot())['this_interval_complete'])
        t=self.trace();c=SubmissionCursor('a'*64,'b'*64);t.event('proposal_requested',attempt=0,scope_id='c'*64)
        c.drain(t.snapshot());t.event('native_call_started',native_action='secret/path',attempt=1)
        self.assertFalse(c.drain(t.snapshot())['this_interval_complete'])
        with self.assertRaises(ValueError):c.drain(self.trace().snapshot())
        bad=copy.deepcopy(t.snapshot());bad['events'][0]['stage']='prepare_start'
        with self.assertRaises(ValueError):SubmissionCursor('a'*64,'b'*64).drain(bad)

    def test_native_exactly_once_success_refusal_and_clock_failure_are_observation_only(self):
        for fail,clock_bad in ((False,False),(True,False),(False,True),(True,True)):
            with self.subTest(fail=fail,clock_bad=clock_bad):
                t=self.trace();calls=[];native=Native.__new__(Native);native.contact_trace=t
                def call(*args,private_input=None):
                    calls.append((args,private_input))
                    if fail:raise ValueError('original Native refusal')
                    return {'synthetic':'no-authority'}
                native._call=call
                with patch('regional_contact_trace.time.monotonic',side_effect=OSError('clock')) if clock_bad else patch('regional_contact_trace.time.monotonic',side_effect=[1.,2.]):
                    if fail:
                        with self.assertRaisesRegex(ValueError,'original Native refusal'):native.call('bft-loop-status',private_input=b'bounded-test')
                    else:self.assertEqual(native.call('bft-loop-status',private_input=b'bounded-test'),{'synthetic':'no-authority'})
                self.assertEqual(calls,[(('bft-loop-status',),b'bounded-test')])
                value=t.snapshot()
                if clock_bad:self.assertGreater(value['rejected_events'],0)
                else:
                    self.assertEqual([r['stage'] for r in value['events']],['native_call_started','native_call_finished'])
                    self.assertEqual(value['events'][0]['attempt'],value['events'][1]['attempt'])
                    self.assertEqual(value['events'][1]['native_success'],not fail)
                self.assertNotIn('bounded-test',str(value))

    def test_default_native_and_full_trace_use_original_call_without_narrow_measurement(self):
        for trace in (None,ContactTrace()):
            n=Native.__new__(Native);n.contact_trace=trace;calls=[]
            n._call=lambda *a,**k:calls.append((a,k)) or 7
            self.assertEqual(n.call('status'),7);self.assertEqual(calls,[(('status',),{'private_input':None})])
            if trace is not None:self.assertEqual(trace.sequence,0)

    def test_exact_four_cold_archive_and_default_reader_refusal(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        root=Path(temp.name);slots={i:(100+i,format(i+1,'064x')) for i in range(4)}
        journal=SubmissionShards('a'*64,slots,deadline=10,path=root/'narrow')
        for i in range(4):
            t=SubmissionTrace();t.bind('a'*64,slots[i][1]);t.event('consensus_tick_started')
            journal.sample(i,dict(process_id=slots[i][0],contact_trace=t.snapshot()),now=1)
        journal.close();snapshot=journal.snapshot()
        self.assertEqual(verify_submission_shards(journal.path,snapshot,network='a'*64,slots=slots)['events'],4)
        with self.assertRaises(ValueError):verify_shards(journal.path,snapshot,network='a'*64,slots=slots)
        with self.assertRaises(ValueError):verify_submission_shards(journal.path,snapshot,network='a'*64,slots={**slots,0:(999,slots[0][1])})
        p=journal.path/'part-00.jsonl';before=p.read_bytes();p.write_bytes(before.replace(b'consensus_tick_started',b'prepare_start'))
        with self.assertRaises(ValueError):verify_submission_shards(journal.path,snapshot,network='a'*64,slots=slots)
        # Even an independently rehashed file/manifest cannot smuggle an
        # unselected transport stage into this narrow declared coverage.
        rows=p.read_bytes().splitlines();changed=dict(snapshot)
        changed.pop('manifest_sha256');changed['parts']=[dict(changed['parts'][0],bytes=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest())]
        changed['journal_bytes']=p.stat().st_size;changed['canonical_event_bytes']=p.stat().st_size+1
        changed['journal_sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
        mesh.atomic(journal.path/'manifest.json',changed);seal=dict(changed,manifest_sha256=hashlib.sha256((journal.path/'manifest.json').read_bytes()).hexdigest())
        with self.assertRaisesRegex(ValueError,'unselected'):verify_submission_shards(journal.path,seal,network='a'*64,slots=slots)


if __name__=='__main__':unittest.main()
