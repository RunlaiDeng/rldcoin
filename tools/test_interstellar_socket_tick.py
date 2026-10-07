"""Socket-only observation does not rewrite idle custody; archives stay durable."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
from test_interstellar_tcp import Fixture as TcpFixture
from test_interstellar_mesh import Fixture as SpoolFixture


class SocketTickTests(unittest.TestCase):
    def setUp(self):
        retained = os.environ.get('RLD_SOCKET_TICK_FIXTURE')
        if retained:
            self.root = Path(retained).resolve() / self._testMethodName
            self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        else:
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            self.root = Path(temporary.name)

    def tcp(self):
        fixture = TcpFixture(self.root, names=('earth', 'proxima'))
        self.addCleanup(fixture.close)
        return fixture

    def test_idle_socket_tick_preserves_complete_pending_bytes_without_state_write(self):
        fixture = self.tcp()
        raw = wire.make_frame('source-finality', '1' * 64, '2' * 64, '4' * 64,
                              wire.canonical({'ground_fixture': 'x' * (96 * 1024)}))
        with fixture.node('earth') as node:
            packets = [node.enqueue(raw, fixture.ids['proxima']) for _ in range(32)]
            original = node.path.read_bytes()
            cursor = node.state['cursor']
            with patch.object(node, 'save', wraps=node.save) as saves:
                report = node.tick()
            self.assertEqual(report['errors'], [])
            self.assertEqual(saves.call_count, 0)
            self.assertEqual(node.state['cursor'], cursor)
            self.assertEqual(node.path.read_bytes(), original)
        mesh._verified_transits.clear()
        with fixture.node('earth') as node:
            self.assertEqual(set(node.state['messages']), set(packets))
            for packet_id in packets:
                _, actual, _ = mesh.transit_check(node.transit(packet_id), node.network)
                self.assertEqual(actual, raw)

    def test_socket_tick_still_archives_complete_receipts_and_cold_reads_every_record(self):
        fixture = self.tcp()
        with fixture.node('earth') as node:
            packets = [node.enqueue(fixture.frame(), fixture.ids['proxima']) for _ in range(32)]
        # Eight original four-packet ground exchanges. No ledger or Native rights.
        for offset in range(0, len(packets), 4):
            with fixture.node('earth') as source:
                bundle = source.prepare_exchange(fixture.ids['proxima'],
                                                 retry_packet_ids=tuple(packets[offset:offset + 4]))
            with fixture.node('proxima') as destination:
                destination.receive(bundle, fixture.ids['earth'])
        with fixture.node('proxima') as node:
            self.assertEqual(set(node.receipts()), set(packets))
            before = len(node.state['archives'])
            cursor = node.state['cursor']
            report = node.tick()
            self.assertEqual(report['errors'], [])
            self.assertGreater(len(node.state['archives']), before)
            self.assertEqual(node.state['cursor'], cursor)
        mesh._verified_transits.clear()
        with fixture.node('proxima') as node:
            self.assertEqual(set(node.receipts()), set(packets))
            for packet_id in node.state['archives']:
                stored = node.archived(packet_id)
                mesh.receipt_matches(stored['receipt'], stored['transit'])

    def test_directory_spool_tick_keeps_original_durable_cursor_and_complete_exchange(self):
        fixture = SpoolFixture(self.root)
        with fixture.node('earth') as node:
            before = node.state['cursor']
            with patch.object(node, 'save', wraps=node.save) as saves:
                report = node.tick()
            self.assertEqual(report['errors'], [])
            self.assertEqual(node.state['cursor'], (before + 1) % (2 ** 63 - 1))
            self.assertGreaterEqual(saves.call_count, 1)
            expected = node.path.read_bytes()
        with fixture.node('earth') as node:
            self.assertEqual(node.path.read_bytes(), expected)


if __name__ == '__main__':
    unittest.main()
