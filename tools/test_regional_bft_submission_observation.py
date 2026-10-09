"""No-value orchestration/diagnostic tests; fake retain grants no Native rights."""
import copy
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_contact_trace import ContactTrace
from regional_bft_submission_observation import read_submissions
from regional_bft_node import Runtime


class SubmissionObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.queue=self.root/'bft-submissions'
        self.queue.mkdir(mode=0o700)
        self.trace=ContactTrace();self.trace.bind('1'*64,'2'*64)
        self.runtime=SimpleNamespace(native=SimpleNamespace(ledger=self.root),
                                     state={'messages':{}},contact_trace=self.trace)
        self.retained=[]
        def retain(envelope,local):
            self.assertTrue(local)
            mesh.atomic(self.root/'retained',envelope)
            self.retained.append(copy.deepcopy(envelope))
            self.runtime.state['messages'][mesh.digest(envelope['body'])]=True
        self.runtime.retain=retain
    def input(self,label,value):
        envelope={'body':{'Submission':[value]},'evidence':{'synthetic':'no-authority'}}
        mesh.atomic(self.queue/label,envelope);return envelope
    def stages(self):return [r['stage'] for r in self.trace.snapshot()['events']]

    def test_complete_retention_precedes_boundary_and_duplicate_preserves_original_work(self):
        first=self.input('a',1);second=self.input('b',2)
        original_event=self.trace.event
        def event(stage,**fields):
            if stage=='submission_retained':
                self.assertTrue((self.root/'retained').exists())
                self.assertEqual(fields['envelope_id'],mesh.digest(self.retained[-1]))
            original_event(stage,**fields)
        self.trace.event=event
        self.assertEqual(read_submissions(self.runtime),2)
        self.assertEqual(self.retained,[first,second])
        self.assertEqual(self.stages(),['submission_scan_started']+
            ['submission_input_read','submission_auth_started','submission_retained']*2+
            ['submission_scan_finished'])
        self.assertEqual(read_submissions(self.runtime),0)
        self.assertEqual(self.retained,[first,second])
        self.assertEqual(self.stages()[-6:],['submission_scan_started','submission_input_read',
            'submission_duplicate_seen','submission_input_read','submission_duplicate_seen',
            'submission_scan_finished'])
        self.assertFalse(self.trace.snapshot()['authority'])

    def test_retention_refusal_keeps_original_input_and_never_reports_retained(self):
        self.input('a',1);original=(self.queue/'a').read_bytes()
        self.runtime.retain=lambda *a,**k:(_ for _ in ()).throw(OSError('retention refused'))
        with self.assertRaisesRegex(OSError,'retention refused'):read_submissions(self.runtime)
        self.assertEqual(self.stages(),['submission_scan_started','submission_input_read',
            'submission_auth_started','submission_retention_failed'])
        self.assertEqual((self.queue/'a').read_bytes(),original)
        self.assertFalse(self.runtime.state['messages']);self.assertFalse(self.retained)

    def test_diagnostic_failure_cannot_skip_retention_or_change_result(self):
        e=self.input('a',1)
        self.trace.event=lambda *a,**k:(_ for _ in ()).throw(OSError('diagnostic refused'))
        self.assertEqual(read_submissions(self.runtime),1);self.assertEqual(self.retained,[e])
        self.assertGreater(self.trace.snapshot()['rejected_events'],0)

    def test_exact_original_count_byte_private_file_and_decode_refusals(self):
        for i in range(33):self.input(str(i),i)
        with self.assertRaisesRegex(ValueError,'spool capacity'):read_submissions(self.runtime)
        self.assertEqual(self.stages(),['submission_scan_started']);self.assertFalse(self.retained)
        self.setUp()  # Keep the separate capacity-refused fixture untouched.
        self.input('a',1);before=(self.queue/'a').read_bytes()
        with patch.object(wire,'MAX_PAYLOAD',1),self.assertRaises(ValueError):read_submissions(self.runtime)
        self.assertEqual((self.queue/'a').read_bytes(),before);self.assertFalse(self.retained)
        (self.queue/'a').chmod(0o644)
        with self.assertRaises(ValueError):read_submissions(self.runtime)
        self.assertFalse(self.retained)

    def test_tick_boundaries_return_failure_and_operation_cleanup_without_authority(self):
        runtime=SimpleNamespace(contact_trace=self.trace,observation=None)
        runtime._tick=lambda: {'synthetic':True}
        self.assertEqual(Runtime.tick(runtime),{'synthetic':True})
        self.assertEqual(self.stages(),['consensus_tick_started','consensus_tick_finished'])
        self.assertIsNone(runtime._tick_operation)
        runtime._tick=lambda:(_ for _ in ()).throw(ValueError('native phase refused'))
        with self.assertRaisesRegex(ValueError,'native phase refused'):Runtime.tick(runtime)
        self.assertEqual(self.stages()[-2:],['consensus_tick_started','consensus_tick_finished'])
        self.assertIsNone(runtime._tick_operation)
        self.assertIsNone(runtime._composed_phase_observation)


if __name__=='__main__':unittest.main()
