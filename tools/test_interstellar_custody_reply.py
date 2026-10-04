"""Actual pinned TLS custody replies; independent reverse carriage stays live."""
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_tcp as tcp
from regional_carriage_worker import Worker
from test_interstellar_tcp import Fixture


class CustodyReplyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(self.temp.name, names=('earth', 'proxima'))
        self.addCleanup(self.f.close)

    def blocked_worker(self):
        server = self.f.servers['proxima']
        entered, release = threading.Event(), threading.Event()
        original = server._outbound_tick
        def blocked():
            entered.set()
            release.wait()
            return original()
        manager = patch.object(server, '_outbound_tick', blocked)
        manager.start()
        self.addCleanup(manager.stop)
        worker = Worker(server, interval=3600)
        self.addCleanup(worker.close)
        self.addCleanup(release.set)
        self.assertTrue(entered.wait(2))
        return worker, release

    def enqueue(self, source, target, index=0):
        with self.f.node(source) as node:
            return node.enqueue(self.f.frame(index), self.f.ids[target])

    def test_durable_reply_does_not_prepare_reverse_batch_then_worker_delivers_it(self):
        forward = self.enqueue('earth', 'proxima')
        reverse = self.enqueue('proxima', 'earth', 1)
        worker, release = self.blocked_worker()
        with self.f.node('proxima') as node:
            before = {key: node.state[key].copy() if isinstance(node.state[key], dict) else node.state[key]
                      for key in ('cursor', 'transit_cursors', 'receipt_cursors', 'requested_receipt_cursors')}
        writes = []
        original = mesh.atomic
        def atomic(path, value):
            if path == self.f.root/'proxima/mesh-state.json':
                writes.append(path)
            return original(path, value)
        with patch.object(mesh, 'atomic', atomic):
            result = self.f.servers['earth'].tick()
        self.assertEqual(result['errors'], [])
        self.assertEqual(len(writes), 1)
        with self.f.node('proxima') as node:
            self.assertIn(forward, node.receipts())
            self.assertEqual({key: node.state[key] for key in before}, before)
        with self.f.node('earth') as node:
            self.assertIn(forward, node.receipts())
            self.assertNotIn(reverse, node.state['messages'])
        release.set()
        deadline = time.monotonic()+5
        while time.monotonic() < deadline and worker.snapshot()['worker']['completed_passes'] == 0:
            time.sleep(0.01)
        self.assertEqual(worker.snapshot()['worker']['completed_passes'], 1)
        with self.f.node('earth') as node:
            self.assertIn(reverse, node.receipts())
            self.assertEqual(node.receipts()[reverse]['body']['outcome'], 'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')

    def test_failed_destination_publication_never_acknowledges_or_suppresses(self):
        ident = self.enqueue('earth', 'proxima')
        self.blocked_worker()
        original = mesh.Node.receive
        def refused(node, *args):
            if node.id == self.f.ids['proxima']:
                raise OSError('destination fsync failure')
            return original(node, *args)
        with patch.object(mesh.Node, 'receive', refused):
            self.assertTrue(self.f.servers['earth'].tick()['errors'])
        self.assertEqual(self.f.servers['earth'].suppressed(self.f.ids['proxima']), set())
        with self.f.node('proxima') as node:
            self.assertNotIn(ident, node.receipts())
        with self.f.node('earth') as node:
            self.assertIn(ident, node.state['messages'])

    def test_verified_reply_still_needs_source_local_custody_before_suppression(self):
        ident = self.enqueue('earth', 'proxima')
        self.blocked_worker()
        original = mesh.Node.receive
        def refused(node, *args):
            if node.id == self.f.ids['earth']:
                raise OSError('source reply custody failure')
            return original(node, *args)
        with patch.object(mesh.Node, 'receive', refused):
            self.assertTrue(self.f.servers['earth'].tick()['errors'])
        self.assertEqual(self.f.servers['earth'].suppressed(self.f.ids['proxima']), set())
        with self.f.node('proxima') as node:
            self.assertIn(ident, node.receipts())
        self.assertEqual(self.f.servers['earth'].tick()['errors'], [])
        self.assertTrue(self.f.servers['earth'].suppressed(self.f.ids['proxima']))
        with self.f.node('earth') as node:
            self.assertIn(ident, node.receipts())

    def test_tightened_reply_bound_refuses_but_keeps_real_destination_custody(self):
        ident = self.enqueue('earth', 'proxima')
        self.blocked_worker()
        with patch.object(tcp, 'MAX_CUSTODY_REPLY_BYTES', 1):
            self.assertTrue(self.f.servers['earth'].tick()['errors'])
        self.assertEqual(self.f.servers['earth'].suppressed(self.f.ids['proxima']), set())
        with self.f.node('proxima') as node:
            self.assertIn(ident, node.receipts())
        self.assertEqual(self.f.servers['earth'].tick()['errors'], [])

    def test_unowned_server_keeps_original_duplex_delivery(self):
        forward = self.enqueue('earth', 'proxima')
        reverse = self.enqueue('proxima', 'earth', 1)
        self.assertEqual(self.f.servers['earth'].tick()['errors'], [])
        with self.f.node('earth') as node:
            self.assertIn(forward, node.receipts())
            self.assertIn(reverse, node.receipts())

    def test_three_live_workers_deliver_multihop_and_return_the_real_receipt(self):
        fixture = Fixture(self.f.root/'three-live-carriers')
        self.addCleanup(fixture.close)
        with fixture.node('earth') as node:
            ident = node.enqueue(fixture.frame(2), fixture.ids['andromeda'])
        for server in fixture.servers.values():
            self.addCleanup(Worker(server, interval=0.1).close)
        deadline = time.monotonic()+10
        delivered = False
        while time.monotonic() < deadline:
            with fixture.node('earth') as node:
                delivered = ident in node.receipts()
            if delivered:
                break
            time.sleep(0.02)
        self.assertTrue(delivered)
        with fixture.node('andromeda') as node:
            self.assertIn(ident, node.receipts())
            mesh.receipt_matches(node.receipts()[ident], node.transit(ident))
        with fixture.node('earth') as node:
            self.assertEqual(node.receipts()[ident]['body']['outcome'], 'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')


if __name__ == '__main__':
    unittest.main()
