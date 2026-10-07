"""Expired process-only retry intent; full signed ground custody stays ordinary."""
import errno
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest

import interstellar_mesh as mesh
import interstellar_tcp as tcp
import interstellar_transfer as wire
from test_interstellar_tcp import Fixture


class SelectionExpiryTests(unittest.TestCase):
    def setUp(self):
        retained = os.environ.get('RLD_SELECTION_EXPIRY_FIXTURE')
        if retained:
            root = Path(retained).resolve() / self._testMethodName
            root.mkdir(mode=0o700, parents=True, exist_ok=False)
        else:
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            root = Path(temporary.name)
        self.f = Fixture(root, names=('earth', 'proxima'))
        self.addCleanup(self.f.close)
        self.server = self.f.servers['earth']

    def bounded_refusal(self):
        # Real OS lock contention. The original bounded attempt leaves only
        # scheduling intent; no acquired Node or decoded request survives.
        held = self.f.node('earth')
        try:
            self.server.request_selection('receive')
            with self.assertRaises(BlockingIOError) as caught:
                with self.server.selection_mesh_node(
                        time.monotonic() + tcp.MAX_LOCAL_LOCK_WAIT_SECONDS):
                    self.fail('held original mesh lock was bypassed')
            self.assertIn(caught.exception.errno, (errno.EAGAIN, errno.EWOULDBLOCK))
        finally:
            held.close()
        self.assertIsNone(self.server.local_mesh_owner)
        self.assertIsNone(self.server.selection_attempt_owner)
        self.assertGreater(self.server.selection_preference_until, 0)

    def test_expired_refusal_allows_same_owner_carriage_and_full_signed_tls_receipt(self):
        raw = wire.make_frame('source-finality', '1' * 64, '2' * 64,
                              '4' * 64, b'{"ground_fixture":true}')
        with self.f.node('earth') as node:
            packet_id = node.enqueue(raw, self.f.ids['proxima'])
            original_packet = node.state['messages'][packet_id]['packet']
            original_route = node.state['messages'][packet_id]['routing']
        self.bounded_refusal()
        time.sleep(max(0, self.server.selection_preference_until - time.monotonic()) + .01)
        with self.server.ordinary_mesh_node() as node:
            self.assertEqual(node.state['messages'][packet_id]['packet'], original_packet)
            self.assertEqual(node.state['messages'][packet_id]['routing'], original_route)
        self.assertIsNone(self.server.selection_owner)
        self.assertEqual(self.server.tick()['errors'], [])
        mesh._verified_transits.clear()
        with self.f.node('proxima') as node:
            transit = node.transit(packet_id)
            _, actual, _ = mesh.transit_check(transit, node.network)
            self.assertEqual(actual, raw)
            receipt = node.receipts()[packet_id]
            mesh.receipt_matches(receipt, transit)
            self.assertEqual(receipt['body']['outcome'], 'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')

    def test_live_preference_and_initial_unattempted_intent_keep_original_purpose(self):
        self.server.request_selection('receive')
        for preference in (0, time.monotonic() + tcp.MAX_LOCAL_LOCK_WAIT_SECONDS):
            self.server.selection_preference_until = preference
            with self.assertRaises(BlockingIOError):
                self.server.request_selection('carriage')
            self.assertEqual(self.server.selection_purpose, 'receive')
            self.assertIs(self.server.selection_owner, threading.current_thread())
        self.server.finish_selection()

    def test_active_attempt_keeps_purpose_even_with_expired_preference(self):
        self.server.request_selection('receive')
        with self.server.selection_mesh_node(
                time.monotonic() + tcp.MAX_LOCAL_LOCK_WAIT_SECONDS):
            self.server.selection_preference_until = time.monotonic() - .01
            with self.assertRaises(BlockingIOError):
                self.server.request_selection('carriage')
            self.assertEqual(self.server.selection_purpose, 'receive')
        self.server.finish_selection()


if __name__ == '__main__':
    unittest.main()
