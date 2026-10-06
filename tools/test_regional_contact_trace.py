"""Live transport boundaries and explicit observation loss; no value pass."""
import copy
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_tcp as tcp
from regional_contact_trace import ContactTrace,TraceCursor,TracePublisher,MAX_EVENTS,MAX_BYTES
from test_interstellar_tcp import Fixture,NETWORK


class TraceTests(unittest.TestCase):
    def trace(self):
        trace=ContactTrace();trace.bind('a'*64,'b'*64)
        return trace

    def test_strict_primitive_metadata_never_retains_payload_or_private_fields(self):
        trace=self.trace()
        trace.event('source_enqueued','c'*64,packet_id='d'*64,envelope_id='e'*64)
        for fields in ({'private_key':'secret'},{'packet_id':{}},{'attempt':True},{'failure_stage':'private/path'}):
            trace.event('outgoing_failed',**fields)
        row=trace.snapshot()
        self.assertEqual(len(row['events']),1)
        self.assertEqual(row['rejected_events'],4)
        self.assertNotIn('secret',json.dumps(row))
        self.assertFalse(row['authority'])
        with self.assertRaises(ValueError):trace.bind('a'*64,'c'*64)

    def test_ring_eviction_and_rejections_are_explicit_gaps(self):
        trace=self.trace();cursor=TraceCursor('a'*64,'b'*64)
        for _ in range(MAX_EVENTS+3):trace.event('contact_start','c'*64,attempt=1)
        delta=cursor.drain(trace.snapshot())
        self.assertEqual(delta['missed_events'],3)
        self.assertFalse(delta['this_interval_complete'])
        self.assertEqual(len(delta['events']),MAX_EVENTS)
        self.assertEqual(cursor.drain(trace.snapshot())['events'],[])
        trace.event('wrong',password='never retained')
        self.assertFalse(cursor.drain(trace.snapshot())['this_interval_complete'])

    def test_cursor_refuses_changed_binding_event_counter_and_restart(self):
        trace=self.trace();trace.event('contact_start');value=trace.snapshot()
        cursor=TraceCursor('a'*64,'b'*64);cursor.drain(value)
        for changed in (dict(value,binding=['a'*64,'c'*64]),dict(value,sequence=0),dict(value,evicted_events=2)):
            with self.assertRaises(ValueError):cursor.drain(changed)
        changed=copy.deepcopy(value);changed['events'][0]['stage']='contact_failed'
        with self.assertRaisesRegex(ValueError,'event changed'):cursor.drain(changed)
        changed=copy.deepcopy(value);changed['events'][0]['peer']={'secret':'not a primitive'}
        with self.assertRaises(ValueError):cursor.drain(changed)

    def test_threads_keep_exact_sequence_and_clock_failure_is_diagnostic_only(self):
        trace=self.trace()
        threads=[threading.Thread(target=lambda:[trace.event('contact_start') for _ in range(30)]) for _ in range(3)]
        for thread in threads:thread.start()
        for thread in threads:thread.join()
        row=trace.snapshot();self.assertEqual(row['sequence'],90)
        self.assertEqual([x['sequence'] for x in row['events']],list(range(1,91)))
        with patch('regional_contact_trace.time.monotonic',side_effect=OSError('clock unavailable')):trace.event('contact_start')
        self.assertEqual(trace.snapshot()['rejected_events'],1)

    def test_primitive_publisher_runs_without_service_tick_and_stops(self):
        with tempfile.TemporaryDirectory() as root:
            trace=self.trace();path=Path(root)/'publication'
            publisher=TracePublisher(trace,path)
            try:
                trace.event('contact_start','c'*64)
                end=time.monotonic()+2
                while mesh.load(path,MAX_BYTES)['contact_trace']['sequence']!=1 and time.monotonic()<end:
                    time.sleep(.02)
                value=mesh.load(path,MAX_BYTES)
                self.assertEqual(value['process_id'],os.getpid())
                self.assertEqual(value['contact_trace']['sequence'],1)
                self.assertFalse(value['publisher_failed'])
                self.assertNotIn('private_key',json.dumps(value))
                with self.assertRaisesRegex(ValueError,'cannot resume'):TracePublisher(trace,path)
            finally:publisher.close()
            self.assertFalse(publisher.thread.is_alive())

    def test_failed_publisher_keeps_failure_without_authority(self):
        with tempfile.TemporaryDirectory() as root:
            trace=self.trace();path=Path(root)/'publication';publisher=TracePublisher(trace,path)
            try:
                with patch('regional_contact_trace.mesh.atomic',side_effect=OSError('disk refusal')):
                    end=time.monotonic()+2
                    while publisher.failure is None and time.monotonic()<end:time.sleep(.02)
                    self.assertEqual(publisher.failure,'OSError')
                publisher.publish();value=mesh.load(path,MAX_BYTES)
                self.assertTrue(value['publisher_failed'])
                self.assertFalse(value['contact_trace']['available'])
                self.assertFalse(value['contact_trace']['authority'])
            finally:publisher.close()

    def test_publisher_byte_bound_refuses_without_replacing_previous(self):
        with tempfile.TemporaryDirectory() as root:
            trace=self.trace();path=Path(root)/'publication';publisher=TracePublisher(trace,path)
            try:
                publisher.stop_event.set();publisher.thread.join(timeout=2)
                before=path.read_bytes()
                with patch('regional_contact_trace.MAX_BYTES',1):
                    with self.assertRaisesRegex(ValueError,'byte capacity'):publisher.publish()
                self.assertEqual(path.read_bytes(),before)
            finally:publisher.close()

    def test_publisher_failure_does_not_leak_service_ownership_lock(self):
        from regional_contact_node import Service
        from types import SimpleNamespace
        with tempfile.TemporaryFile() as stream:
            service=object.__new__(Service);service.carriage=service.bft=service.tcp=None
            service.lock=os.dup(stream.fileno());fd=service.lock
            service.trace_publisher=SimpleNamespace(close=lambda:(_ for _ in ()).throw(OSError('diagnostic fsync')))
            with self.assertRaises(OSError):service.close()
            self.assertIsNone(service.lock)
            with self.assertRaises(OSError):os.fstat(fd)

    def traced_fixture(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        fixture=Fixture(temporary.name,names=('earth','proxima'));self.addCleanup(fixture.close)
        traces={name:ContactTrace() for name in fixture.names}
        for name in fixture.names:fixture.stop(name)
        for name in fixture.names:
            fixture.servers[name]=tcp.Server(fixture.configs[name],('127.0.0.1',fixture.ports[name]),contact_trace=traces[name])
        return fixture,traces

    def test_actual_pinned_TLS_links_prepare_peer_and_destination_custody(self):
        fixture,traces=self.traced_fixture();raw=fixture.frame(905)
        with fixture.node('earth') as node:ident=node.enqueue(raw,fixture.ids['proxima'])
        fixture.servers['earth'].tick()
        with fixture.node('proxima') as node:self.assertIn(ident,node.receipts())
        source=[x for x in traces['earth'].snapshot()['events'] if x.get('packet_id')==ident]
        target=[x for x in traces['proxima'].snapshot()['events'] if x.get('packet_id')==ident]
        self.assertTrue({'outgoing_prepared','request_sent','peer_custody_authenticated','reply_local_custody'}<=set(x['stage'] for x in source))
        self.assertTrue({'request_authenticated','local_transport_custody','destination_receipt_retained'}<=set(x['stage'] for x in target))
        source_nonce={x['nonce'] for x in source if x['stage']=='request_sent'}
        target_nonce={x['nonce'] for x in target if x['stage']=='destination_receipt_retained'}
        self.assertEqual(source_nonce,target_nonce)

    def test_durable_custody_observed_even_if_reply_preparation_fails(self):
        fixture,traces=self.traced_fixture()
        # Actual live independent owner selects the custody-only response path.
        fixture.servers['proxima'].outbound_owner=threading.current_thread()
        with fixture.node('earth') as node:ident=node.enqueue(fixture.frame(906),fixture.ids['proxima'])
        with patch('interstellar_tcp._custody_reply',side_effect=ValueError('reply bound refused')):
            fixture.servers['earth'].tick()
        stages={x['stage'] for x in traces['proxima'].snapshot()['events'] if x.get('packet_id')==ident}
        self.assertIn('destination_receipt_retained',stages)
        self.assertIn('inbound_refused',stages)
        with fixture.node('proxima') as node:self.assertIn(ident,node.receipts())
        with fixture.node('earth') as node:self.assertNotIn(ident,node.receipts())

    def test_failed_destination_publication_cannot_emit_custody_event(self):
        fixture,traces=self.traced_fixture()
        with fixture.node('earth') as node:ident=node.enqueue(fixture.frame(907),fixture.ids['proxima'])
        original=mesh.atomic;target=fixture.root/'proxima'/'mesh-state.json'
        def refused(path,value):
            if path==target:raise OSError('destination publication refused')
            return original(path,value)
        with patch('interstellar_mesh.atomic',side_effect=refused):fixture.servers['earth'].tick()
        stages={x['stage'] for x in traces['proxima'].snapshot()['events'] if x.get('packet_id')==ident}
        self.assertIn('inbound_refused',stages)
        self.assertNotIn('destination_receipt_retained',stages)
        self.assertNotIn('local_transport_custody',stages)
        with fixture.node('earth') as node:self.assertNotIn(ident,node.receipts())


if __name__=='__main__':unittest.main()
