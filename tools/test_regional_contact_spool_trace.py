"""Directory timing boundaries with no-value frames; no Native authority."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_contact_trace import ContactTrace
from test_interstellar_mesh import Fixture, NETWORK


class SpoolTraceTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix='rld-spool-trace-')
        self.addCleanup(temporary.cleanup)
        fixture = Fixture(temporary.name)
        fixture.rounds()
        return fixture

    def attach(self, node):
        trace = ContactTrace()
        trace.bind(NETWORK, node.id)
        node.contact_trace = trace
        return trace

    def stages(self, trace, packet):
        return [r['stage'] for r in trace.snapshot()['events']
                if r.get('packet_id') == packet]

    def test_complete_roundtrip_has_distinct_publication_read_and_custody(self):
        fixture = self.fixture()
        peer = fixture.identities['proxima']['node_id']
        with fixture.node('earth') as node:
            trace = self.attach(node)
            packet = node.enqueue(fixture.frame(), peer)
            self.assertEqual(node.flush_spool_outgoing(), [])
            self.assertIn('spool_outgoing_published', self.stages(trace, packet))
            self.assertNotIn(packet, node.receipts())
        with fixture.node('proxima') as node:
            trace = self.attach(node)
            self.assertEqual(node.tick(defer_spool_outgoing=True)['errors'], [])
            self.assertEqual(self.stages(trace, packet),
                             ['spool_incoming_read', 'spool_incoming_custody'])
            self.assertIn(packet, node.receipts())
            self.assertFalse(trace.snapshot()['authority'])
        with fixture.node('proxima') as cold:
            self.assertIn(packet, cold.receipts())
            self.assertEqual(mesh.transit_check(cold.transit(packet), NETWORK)[1], fixture.frame())

    def test_failed_publication_never_reports_outgoing_success(self):
        fixture = self.fixture()
        with fixture.node('earth') as node:
            trace = self.attach(node)
            packet = node.enqueue(fixture.frame(), fixture.identities['proxima']['node_id'])
            before = wire.canonical(node.state['messages'][packet])
            write_new=wire.write_new
            def refused(path,data):
                if Path(path).parent in [contact['outbox'] for contact in node.contacts.values()]:
                    raise OSError('spool write refused')
                return write_new(path,data)
            with patch.object(wire, 'write_new', side_effect=refused):
                self.assertEqual(node.flush_spool_outgoing(), ['spool write refused'])
            self.assertEqual(self.stages(trace, packet), ['prepare_selected', 'prepare_retained'])
            self.assertEqual(wire.canonical(node.state['messages'][packet]), before)
            self.assertNotIn(packet, node.receipts())

    def test_bad_signature_or_failed_custody_keeps_input_without_custody_event(self):
        for fault in ('signature', 'custody'):
            with self.subTest(fault=fault):
                fixture = self.fixture()
                peer = fixture.identities['proxima']['node_id']
                with fixture.node('earth') as node:
                    packet = node.enqueue(fixture.frame(), peer)
                    bundle = node.prepare_exchange(peer)
                    directory = node.contacts[peer]['outbox']
                if fault == 'signature':bundle['signature'] = '0' * 128
                raw = wire.canonical(bundle)
                path = directory / (mesh.digest(bundle) + '.json')
                wire.write_new(path, raw)
                with fixture.node('proxima') as node:
                    trace = self.attach(node)
                    before = copy.deepcopy({k:node.state[k] for k in ('messages','receipts')})
                    if fault == 'custody':
                        receive = node.receive
                        def refused(bundle, peer):
                            with patch.object(mesh, 'atomic', side_effect=OSError('custody refused')):
                                return receive(bundle, peer)
                        with patch.object(node, 'receive', side_effect=refused):
                            result = node.tick(defer_spool_outgoing=True)
                    else:result = node.tick(defer_spool_outgoing=True)
                    self.assertTrue(result['errors'])
                    self.assertEqual(self.stages(trace, packet), ['spool_incoming_read'])
                    self.assertEqual(path.read_bytes(), raw)
                    self.assertEqual({k:node.state[k] for k in before}, before)

    def test_diagnostic_failure_cannot_prevent_actual_publication_or_custody(self):
        fixture = self.fixture()
        peer = fixture.identities['proxima']['node_id']
        with fixture.node('earth') as node:
            trace = self.attach(node)
            packet = node.enqueue(fixture.frame(), peer)
            with patch.object(trace, 'packets', side_effect=ValueError('diagnostic refused')):
                self.assertEqual(node.flush_spool_outgoing(), [])
            self.assertGreater(trace.snapshot()['rejected_events'], 0)
        with fixture.node('proxima') as node:
            trace = self.attach(node)
            with patch.object(trace, 'packets', side_effect=ValueError('diagnostic refused')):
                self.assertEqual(node.tick(defer_spool_outgoing=True)['errors'], [])
            self.assertIn(packet, node.receipts())
            self.assertGreater(trace.snapshot()['rejected_events'], 0)


if __name__ == '__main__':unittest.main()
