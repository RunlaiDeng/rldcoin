"""Retained receipts requested over real pinned TLS without reverse-worker help."""
import copy
import time
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_tcp as tcp
import interstellar_transfer as wire
import test_interstellar_custody_reply as custody_tests


class RequestedCustodyTests(unittest.TestCase):
    setUp = custody_tests.CustodyReplyTests.setUp
    blocked_worker = custody_tests.CustodyReplyTests.blocked_worker
    enqueue = custody_tests.CustodyReplyTests.enqueue
    def preload(self, count):
        identifiers = {self.enqueue('earth', 'proxima', i) for i in range(count)}
        self.accepted_carriage = set()
        with self.f.node('earth') as source, self.f.node('proxima') as destination:
            pending = set(identifiers)
            while pending:
                bundle = source.prepare_exchange(self.f.ids['proxima'], self.accepted_carriage)
                carried = {mesh.digest(t['packet']) for t in bundle['body']['transits']}
                self.assertTrue(carried)
                destination.receive(bundle, source.id)
                self.accepted_carriage.update(mesh.digest(t) for t in bundle['body']['transits'])
                pending -= carried
        return identifiers

    def requested_reply(self, identifiers, change=None):
        peer = self.f.ids['proxima']
        with self.f.node('earth') as source:
            bundle = source.prepare_exchange(peer, self.accepted_carriage)
            self.assertEqual(bundle['body']['transits'], [])
            key, network, requester = source.key, source.network, source.id
            if change:
                bundle = change(source, bundle)
        deadline = time.monotonic()+tcp.ATTEMPT_SECONDS
        with tcp.client_connect(self.f.servers['proxima'].address, self.f.pins['proxima'],
                                network, peer, deadline) as connection:
            nonce = tcp.check_challenge(tcp.receive(connection, deadline), network, peer,
                                        self.f.pins['proxima'])
            sent = tcp.bind_request(key, network, requester, peer, nonce, bundle)
            tcp.send(connection, sent, deadline)
            response = tcp.check_response(tcp.receive(connection, deadline), network, requester, peer, sent)
        return response

    def test_retained_destination_receipt_returns_without_original_transit(self):
        identifiers = self.preload(1)
        self.blocked_worker()
        bundle = self.requested_reply(identifiers)
        self.assertEqual({mesh.receipt_check(r, self.f.configs['earth']['network'])
                          for r in bundle['body']['receipts']}, identifiers)
        with self.f.node('earth') as source:
            self.assertFalse(source.receipts())
            source.receive(bundle, self.f.ids['proxima'])
            self.assertEqual(set(source.receipts()), identifiers)
            self.assertEqual(next(iter(source.receipts().values()))['body']['outcome'],
                             'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')

    def test_more_than_one_batch_rotates_even_when_completed_ids_stay_advertised(self):
        identifiers = self.preload(35)
        self.blocked_worker()
        with self.f.node('proxima') as destination:
            before = copy.deepcopy({k: destination.state[k] for k in
                ('cursor', 'transit_cursors', 'receipt_cursors', 'requested_receipt_cursors')})
        returned = set()
        for _ in range(3):
            bundle = self.requested_reply(identifiers)
            self.assertLessEqual(len(bundle['body']['receipts']), mesh.MAX_RECEIPT_BATCH)
            self.assertEqual(bundle['body']['transits'], [])
            returned.update(mesh.receipt_check(r, self.f.configs['earth']['network'])
                            for r in bundle['body']['receipts'])
        self.assertEqual(returned, identifiers)
        with self.f.node('proxima') as destination:
            self.assertEqual({k: destination.state[k] for k in before}, before)

    def test_corrupt_signed_inventory_never_advances_reply_rotation(self):
        identifiers = self.preload(2)
        self.blocked_worker()
        server = self.f.servers['proxima']
        before = copy.deepcopy(server.custody_receipt_after)
        def corrupt(source, bundle):
            body = copy.deepcopy(bundle['body'])
            body['inventory']['signature'] = '0'*128
            return mesh.sign(source.key, 'exchange', body)
        with self.assertRaisesRegex(ValueError, 'refused custody'):
            self.requested_reply(identifiers, corrupt)
        self.assertEqual(server.custody_receipt_after, before)
        returned = self.requested_reply(identifiers)
        self.assertEqual({r['body']['packet_id'] for r in returned['body']['receipts']}, identifiers)

    def test_failed_received_inventory_publication_cannot_return_requested_receipts(self):
        identifiers = self.preload(2)
        self.blocked_worker()
        server = self.f.servers['proxima']
        before = copy.deepcopy(server.custody_receipt_after)
        with patch.object(mesh, 'sync_retained', side_effect=OSError('retained fsync refused')):
            with self.assertRaisesRegex(ValueError, 'refused custody'):
                self.requested_reply(identifiers)
        self.assertEqual(server.custody_receipt_after, before)
        with self.f.node('proxima') as destination:
            self.assertTrue(identifiers <= set(destination.receipts()))

    def test_byte_bound_rotates_only_actually_selected_requested_receipts(self):
        identifiers = self.preload(5)
        self.blocked_worker()
        # Each exact routing proof has equal size; permit just one receipt.
        with self.f.node('proxima') as destination:
            receipt = next(iter(destination.receipts().values()))
        first = self.requested_reply(identifiers)
        base_size = len(wire.canonical(first))-sum(len(wire.canonical(r))
                     for r in first['body']['receipts'])-(len(first['body']['receipts'])-1)
        bound = base_size+len(wire.canonical(receipt))+1024
        returned = set()
        with patch.object(tcp, 'MAX_CUSTODY_REPLY_BYTES', bound):
            for _ in range(5):
                bundle = self.requested_reply(identifiers)
                self.assertEqual(len(bundle['body']['receipts']), 1)
                self.assertLessEqual(len(wire.canonical(bundle))+1024, bound)
                returned.add(mesh.receipt_check(bundle['body']['receipts'][0],
                                                self.f.configs['earth']['network']))
        self.assertEqual(returned, identifiers)


if __name__ == '__main__':
    unittest.main()
