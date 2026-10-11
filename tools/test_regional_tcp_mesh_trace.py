"""Actual pinned TLS Mesh operation tracing; no Native value authority."""
import tempfile
import time
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
from regional_contact_trace import ContactTrace, TraceCursor
from test_interstellar_tcp import Fixture, NETWORK


class TcpMeshTraceTests(unittest.TestCase):
    def fixture(self):
        temporary=tempfile.TemporaryDirectory(prefix='rld-tcp-mesh-trace-')
        self.addCleanup(temporary.cleanup)
        fixture=Fixture(temporary.name,names=('earth','proxima'))
        self.addCleanup(fixture.close)
        return fixture

    def delivery(self, fixture):
        raw=fixture.frame()
        with fixture.node('earth') as node:
            packet=node.enqueue(raw,fixture.ids['proxima'])
        fixture.rounds(3)
        with fixture.node('proxima') as node:
            self.assertIn(packet,node.receipts())
            self.assertEqual(mesh.transit_check(node.transit(packet),NETWORK)[1],raw)
            self.assertFalse(node.status()['payment_authorized'])
        return packet

    def test_actual_tls_prepare_hooks_bind_selected_and_durable_packets(self):
        fixture=self.fixture()
        server=fixture.servers['earth']
        trace=ContactTrace();trace.bind(NETWORK,fixture.ids['earth'])
        server.contact_trace=trace
        packet=self.delivery(fixture)
        rows=TraceCursor(NETWORK,fixture.ids['earth']).drain(trace.snapshot())
        self.assertTrue(rows['this_interval_complete'])
        selected=[r for r in rows['events'] if r['stage']=='prepare_selected']
        retained=[r for r in rows['events'] if r['stage']=='prepare_retained']
        self.assertIn(packet,[r['packet_id'] for r in selected])
        self.assertEqual([(r['packet_id'],r['frame_id']) for r in selected],
                         [(r['packet_id'],r['frame_id']) for r in retained])
        self.assertIn('prepare_start',[r['stage'] for r in rows['events']])
        self.assertIn('prepare_selection',[r['stage'] for r in rows['events']])
        self.assertFalse(trace.snapshot()['authority'])

    def test_disabled_and_refused_prepare_observation_preserve_actual_custody(self):
        for refused in (False,True):
            with self.subTest(refused=refused):
                fixture=self.fixture();server=fixture.servers['earth']
                if not refused:
                    with server.mesh_node(time.monotonic()+3) as node:
                        self.assertIsNone(node.contact_trace)
                    self.delivery(fixture)
                else:
                    trace=ContactTrace();trace.bind(NETWORK,fixture.ids['earth'])
                    server.contact_trace=trace;original=trace.event
                    def observe(stage,*args,**kwargs):
                        if stage.startswith('prepare_'):
                            raise OSError('diagnostic preparation observation refused')
                        return original(stage,*args,**kwargs)
                    with patch.object(trace,'event',side_effect=observe):
                        self.delivery(fixture)
                    self.assertGreater(trace.snapshot()['rejected_events'],0)
                    self.assertFalse(TraceCursor(NETWORK,fixture.ids['earth']).drain(
                        trace.snapshot())['this_interval_complete'])


if __name__=='__main__':unittest.main()
