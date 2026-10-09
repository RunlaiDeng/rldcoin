"""Operation boundary observations only; models grant no Native authority."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import regional_bft_live_batch as batch
from regional_bft_node import Runtime
from regional_contact_trace import ContactTrace,TraceCursor
from test_interstellar_mesh import Fixture,NETWORK
import test_regional_bft_live_batch as origin_fixture


class ReceiveServiceTraceTests(unittest.TestCase):
    def trace(self,network,node):
        trace=ContactTrace();trace.bind(network,node);return trace

    def test_complete_encoded_file_has_visible_read_decode_and_authenticated_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture=Fixture(directory)
            for config in fixture.configs.values():
                for contact in config['contacts']:contact['adapter']=mesh.spool_codec.FORMAT
            fixture.rounds()
            peer=fixture.identities['proxima']['node_id']
            with fixture.node('earth') as node:
                trace=self.trace(NETWORK,node.id);node.contact_trace=trace
                ident=node.enqueue(fixture.frame(),peer);self.assertEqual(node.flush_spool_outgoing(),[])
                published=[e for e in trace.snapshot()['events'] if e['stage']=='spool_outgoing_published' and e['packet_id']==ident]
                self.assertTrue(published);exchange=published[0]['exchange_id']
            with fixture.node('proxima') as node:
                trace=self.trace(NETWORK,node.id);node.contact_trace=trace
                self.assertEqual(node.tick(defer_spool_outgoing=True)['errors'],[])
                events=[e for e in trace.snapshot()['events'] if e.get('exchange_id')==exchange]
                self.assertEqual([e['stage'] for e in events],['spool_incoming_discovered',
                    'spool_incoming_read_started','spool_incoming_bytes_read',
                    'spool_incoming_decode_started','spool_incoming_decoded','spool_incoming_read'])
                self.assertEqual(events[-1]['packet_id'],ident)
                self.assertIn(ident,node.receipts())
                self.assertTrue(TraceCursor(NETWORK,node.id).drain(trace.snapshot())['this_interval_complete'])
                self.assertFalse(trace.snapshot()['authority'])

    def origin(self):
        f=origin_fixture.OriginReceiveBoundaryTests();f.setUp();self.addCleanup(f.temp.cleanup)
        f.runtime.contact_trace=self.trace(f.currency,'a'*64)
        return f

    def test_native_process_return_and_complete_bound_result_are_distinct(self):
        for corrupted in (False,True):
            with self.subTest(corrupted=corrupted):
                f=self.origin()
                if corrupted:f.change=lambda r:{**r,'request_sha256':'0'*64}
                if corrupted:
                    with self.assertRaises(ValueError):batch.receive_origin(f.runtime,f.envelopes)
                else:batch.receive_origin(f.runtime,f.envelopes)
                events=f.runtime.contact_trace.snapshot()['events']
                ident=mesh.digest(f.envelopes[0])
                stages=[e['stage'] for e in events if e['envelope_id']==ident]
                self.assertEqual(stages,['native_head_started','native_head_returned',
                    'native_input_durable','native_validate_call_started','native_validate_call_returned']
                    +([] if corrupted else ['native_validation_bound']))
                self.assertEqual(f.calls,['history-head','bft-origin-network-receive-batch'])
                self.assertEqual(list(f.runtime.root.iterdir()),[])
                self.assertNotIn('history_head',str(events))
                self.assertFalse(f.runtime.contact_trace.snapshot()['authority'])

    def test_failed_input_fsync_and_diagnostic_never_release_false_validation(self):
        f=self.origin()
        with patch.object(batch.os,'fsync',side_effect=OSError('fsync failed')):
            with self.assertRaises(OSError):batch.receive_origin(f.runtime,f.envelopes)
        self.assertEqual(f.calls,['history-head'])
        self.assertFalse(any(e['stage']=='native_validate_call_started' for e in f.runtime.contact_trace.snapshot()['events']))
        f=self.origin()
        with patch.object(f.runtime.contact_trace,'event',side_effect=ValueError('trace refused')):
            rows,context=batch.receive_origin(f.runtime,f.envelopes)
        self.assertEqual(len(rows),4);self.assertEqual(context['parent_height'],0)
        self.assertEqual(f.calls,['history-head','bft-origin-network-receive-batch'])
        self.assertGreater(f.runtime.contact_trace.snapshot()['rejected_events'],0)

    def test_timeout_request_failure_and_retained_response_are_separate(self):
        for fail in (False,True):
            trace=self.trace('a'*64,'b'*64);calls=[]
            def sign(request):
                calls.append(request)
                if fail:raise OSError('caller response refused')
            runtime=SimpleNamespace(contact_trace=trace,observation=None,_sign=sign)
            request={'Timeout':{'context':{'fixture_only':True},'round':0}}
            if fail:
                with self.assertRaises(OSError):Runtime.sign(runtime,request)
            else:Runtime.sign(runtime,request)
            self.assertEqual(calls,[request])
            self.assertEqual([e['stage'] for e in trace.snapshot()['events']],
                ['timeout_requested','timeout_failed' if fail else 'timeout_retained'])
            self.assertFalse(trace.snapshot()['authority'])


if __name__=='__main__':unittest.main()
