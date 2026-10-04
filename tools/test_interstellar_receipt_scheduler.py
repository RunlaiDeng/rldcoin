"""No sockets, native nodes, real value or original private stores."""
import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
import interstellar_mesh as mesh
import interstellar_tcp as tcp
import interstellar_transfer as wire

NETWORK = 'a' * 64


class Fixture:
    def __init__(self, root, count=0, peer_count=4):
        self.root = Path(root).resolve()
        self.identities = [mesh.initialize(self.root / str(i), NETWORK, 'b' * 64, str(i))
                           for i in range(peer_count + 1)]
        self.ids = [item['node_id'] for item in self.identities]
        self.configs = [{'format': mesh.VERSION, 'state': str(self.root / str(i)), 'network': NETWORK,
                        'contacts': [{'peer': other, 'host': '127.0.0.1', 'port': 10000 + j}
                                     for j, other in enumerate(self.ids) if j != i]}
                       for i in range(len(self.ids))]
        with self.node(1) as source, self.node(2) as destination, self.node(0) as carrier:
            for i in range(1, len(self.ids)):
                with (self.node(i) if i > 2 else _NullNode(source if i == 1 else destination)) as neighbor:
                    carrier.state['adverts'][neighbor.id] = copy.deepcopy(neighbor.state['adverts'][neighbor.id])
            for serial in range(count):
                packet_id = hashlib.sha256(str(serial).encode()).hexdigest()
                route = mesh.sign(source.key, 'receipt-route', {'format': mesh.VERSION, 'network': NETWORK,
                    'node_id': source.id, 'packet_id': packet_id, 'destination': destination.id, 'frame_id': 'c' * 64})
                receipt = mesh.sign(destination.key, 'receipt', {'format': mesh.VERSION, 'network': NETWORK,
                    'node_id': destination.id, 'packet_id': packet_id, 'frame_id': 'c' * 64, 'routing': route,
                    'outcome': 'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED'})
                mesh.receipt_check(receipt, NETWORK)
                carrier.state['receipts'][packet_id] = receipt
            carrier.save()
        self.receipt_ids = set(carrier.receipts())

    def node(self, i):
        return mesh.Node(self.configs[i])


class _NullNode:
    def __init__(self, value): self.value = value
    def __enter__(self): return self.value
    def __exit__(self, *_): pass


class ReceiptSchedulerTests(unittest.TestCase):
    def fixture(self, count=0, peer_count=4):
        tmp = tempfile.TemporaryDirectory(prefix='receipt-scheduler-test-')
        self.addCleanup(tmp.cleanup)
        return Fixture(tmp.name, count, peer_count)

    def test_four_outbound_and_ordinary_tick_failed_sends_cover_every_peer(self):
        for count in (5, 15, 64, 256):
            with self.subTest(receipts=count):
                f = self.fixture(count)
                seen = {peer: set() for peer in f.ids[1:]}
                rounds = (count + mesh.MAX_RECEIPT_BATCH - 1) // mesh.MAX_RECEIPT_BATCH
                for _ in range(rounds):
                    # Preparing without transmitting models persistent failed
                    # connections. Each complete tick then cold-opens again.
                    with f.node(0) as carrier:
                        for peer in f.ids[1:]:
                            bundle = tcp.outgoing(carrier, peer)
                            receipts = bundle['body']['receipts']
                            self.assertLessEqual(len(receipts), 16)
                            seen[peer].update(mesh.receipt_check(r, NETWORK) for r in receipts)
                        before = dict(carrier.state['receipt_cursors'])
                        carrier.tick()  # TCP endpoints are skipped; no socket opens.
                        self.assertEqual(carrier.state['receipt_cursors'], before)
                self.assertTrue(all(items == f.receipt_ids for items in seen.values()))
                with f.node(0) as carrier:
                    self.assertEqual(set(carrier.receipts()), f.receipt_ids)
                    self.assertFalse(carrier.status()['payment_authorized'])

    def test_peer_progress_is_independent_and_public_exchange_is_read_only(self):
        f = self.fixture(64)
        with f.node(0) as carrier:
            first = carrier.exchange(f.ids[1])
            before = carrier.path.read_bytes()
            for _ in range(3): tcp.outgoing(carrier, f.ids[1])
            second_peer = tcp.outgoing(carrier, f.ids[2])
            self.assertEqual(first['body']['receipts'], second_peer['body']['receipts'])
            self.assertEqual(carrier.state['receipt_cursors'][f.ids[1]], 48)
            self.assertEqual(carrier.state['receipt_cursors'][f.ids[2]], 16)
            self.assertEqual(carrier.state['receipt_cursors'][f.ids[3]], 0)
            saved = carrier.path.read_bytes()
            carrier.exchange(f.ids[1])
            self.assertEqual(carrier.path.read_bytes(), saved)
            self.assertNotEqual(before, saved)

    def test_failed_preparation_publication_releases_no_bundle_or_cursor(self):
        f = self.fixture(64)
        with f.node(0) as carrier:
            before = copy.deepcopy(carrier.state)
            original = carrier.path.read_bytes()
            with patch.object(mesh, 'atomic', side_effect=OSError('injected cursor fsync failure')):
                with self.assertRaisesRegex(OSError, 'cursor fsync'):
                    tcp.outgoing(carrier, f.ids[1])
            self.assertEqual(carrier.state, before)
            self.assertEqual(carrier.path.read_bytes(), original)
            self.assertEqual(set(carrier.receipts()), f.receipt_ids)

    def test_wire_budget_trim_advances_only_selected_receipts(self):
        f = self.fixture(64)
        with f.node(0) as carrier:
            full = carrier.exchange(f.ids[1])
            one = {**full['body'], 'receipts': full['body']['receipts'][:1]}
            limit = len(wire.canonical(one)) + 512 + 16
            with patch.object(mesh, 'MAX_BATCH', limit):
                first = tcp.outgoing(carrier, f.ids[1])
                self.assertEqual(len(first['body']['receipts']), 1)
                self.assertEqual(carrier.state['receipt_cursors'][f.ids[1]], 1)
                second = tcp.outgoing(carrier, f.ids[1])
                self.assertEqual(len(second['body']['receipts']), 1)
                self.assertEqual(carrier.state['receipt_cursors'][f.ids[1]], 2)
            self.assertEqual(first['body']['receipts'][0], full['body']['receipts'][0])
            self.assertEqual(second['body']['receipts'][0], full['body']['receipts'][1])

    def test_spool_keeps_original_one_active_cursor_step_per_complete_tick(self):
        f = self.fixture(5)
        f.configs[0]['contacts'] = [{'peer': peer, 'inbox': str(f.root / ('in-' + str(i))),
                                    'outbox': str(f.root / ('out-' + str(i)))}
                                   for i, peer in enumerate(f.ids[1:])]
        with f.node(0) as carrier:
            before = carrier.state['cursor']
            report = carrier.tick()
            self.assertEqual(report['errors'], [])
            self.assertEqual(carrier.state['cursor'], before + 1)
            self.assertEqual(set(carrier.state['receipt_cursors'].values()), {5})

    def test_old_identity_and_old_state_refuse_without_conversion_or_residue_removal(self):
        for kind in ('identity', 'state'):
            with self.subTest(old=kind):
                f = self.fixture(5)
                root = f.root / '0'
                residue = root / 'archive' / ('.archive-write-' + 'd' * 64)
                residue.write_bytes(b'failed publication retained')
                path = root / ('identity.private.json' if kind == 'identity' else 'mesh-state.json')
                value = mesh.load(path, mesh.MAX_STATE)
                value.pop('receipt_scheduler')
                if kind == 'state': value.pop('receipt_cursors')
                mesh.atomic(path, value)
                before = {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
                with self.assertRaisesRegex(ValueError, 'identity|state'):
                    f.node(0)
                after = {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
                self.assertEqual(after, before)

    def test_changed_scheduler_binding_and_invalid_cursor_refuse(self):
        f = self.fixture(5)
        path = f.root / '0' / 'mesh-state.json'
        original = mesh.load(path, mesh.MAX_STATE)
        for invalid in (-1, 2**63, True, '0'):
            value = copy.deepcopy(original)
            value['receipt_cursors'][f.ids[1]] = invalid
            mesh.atomic(path, value)
            before = path.read_bytes()
            with self.assertRaises(ValueError): f.node(0)
            self.assertEqual(path.read_bytes(), before)
        value = copy.deepcopy(original)
        value['receipt_scheduler'] = 'UNKNOWN-SCHEDULER'
        mesh.atomic(path, value)
        with self.assertRaisesRegex(ValueError, 'state'): f.node(0)

    def test_cursor_metadata_is_contact_bounded_and_original_state_limit_still_refuses(self):
        f = self.fixture(peer_count=mesh.MAX_CONTACTS)
        with f.node(0) as carrier:
            carrier.state['receipt_cursors'] = {peer: 2**63 - 1 for peer in f.ids[1:]}
            carrier.save()
            self.assertEqual(len(carrier.state['receipt_cursors']), mesh.MAX_CONTACTS)
            self.assertLess(len(wire.canonical(carrier.state['receipt_cursors'])), 1600)
            before = carrier.path.read_bytes()
            with patch.object(mesh, 'MAX_STATE', len(before) - 1):
                with self.assertRaisesRegex(ValueError, 'capacity|byte'):
                    tcp.outgoing(carrier, f.ids[1])
            self.assertEqual(carrier.path.read_bytes(), before)
        value = mesh.load(f.root / '0' / 'mesh-state.json', mesh.MAX_STATE)
        value['receipt_cursors']['e' * 64] = 0
        mesh.atomic(f.root / '0' / 'mesh-state.json', value)
        with self.assertRaisesRegex(ValueError, 'cursor capacity'): f.node(0)

    def test_selected_archived_receipts_still_fully_authenticate_and_fsync(self):
        f = self.fixture(5)
        with f.node(0) as carrier, f.node(1) as recipient:
            bundle = tcp.outgoing(carrier, recipient.id)
            recipient.receive(bundle, carrier.id)
            with patch.object(mesh, 'ARCHIVE_HIGH_WATER', 1): recipient.archive_completed()
            archive_read, archive_sync = recipient.archived, recipient.sync_archive
            with patch.object(recipient, 'archived', side_effect=archive_read) as checked, patch.object(recipient, 'sync_archive', side_effect=archive_sync) as synced:
                recipient.receive(bundle, carrier.id)
                self.assertEqual(checked.call_count, 5)
                self.assertEqual(synced.call_count, 5)
            retained = recipient.path.read_bytes()
            with patch.object(recipient, 'sync_archive', side_effect=OSError('injected retained custody fsync')):
                with self.assertRaisesRegex(OSError, 'custody fsync'): recipient.receive(bundle, carrier.id)
            self.assertEqual(recipient.path.read_bytes(), retained)
            altered = copy.deepcopy(bundle['body'])
            altered['receipts'][0]['signature'] = '0' * 128
            hostile = mesh.sign(carrier.key, 'exchange', altered)
            with self.assertRaisesRegex(ValueError, 'signature'): recipient.receive(hostile, carrier.id)
            self.assertEqual(recipient.path.read_bytes(), retained)

    def test_new_transit_and_full_shared_frame_custody_remain_in_the_small_batch(self):
        f = self.fixture(64)
        frame = wire.make_frame('source-finality', 'b' * 64, 'd' * 64, 'c' * 64,
                                b'{"isolated_fixture_no_value":true}')
        with f.node(0) as carrier, f.node(1) as recipient:
            ident = carrier.enqueue(frame, recipient.id)
            bundle = tcp.outgoing(carrier, recipient.id)
            self.assertEqual(len(bundle['body']['receipts']), 16)
            self.assertEqual([mesh.digest(t['packet']) for t in bundle['body']['transits']], [ident])
            recipient.receive(bundle, carrier.id)
            response = tcp.outgoing(recipient, carrier.id)
            carrier.receive(response, recipient.id)
            with patch.object(mesh, 'ARCHIVE_HIGH_WATER', 1):
                while ident not in recipient.state['archives']:
                    self.assertGreater(recipient.archive_completed(), 0)
            # Repeating the same selected transit still reconstructs and fsyncs
            # its complete original frame; no receipt scheduler witness bypass.
            read, sync = recipient.archived, recipient.sync_archive
            with patch.object(recipient, 'archived', side_effect=read) as checked, patch.object(recipient, 'sync_archive', side_effect=sync) as synced:
                recipient.receive(bundle, carrier.id)
                self.assertGreaterEqual(checked.call_count, 1)
                self.assertGreaterEqual(synced.call_count, 1)
            entry = recipient.state['archives'][ident]['body']
            payload = recipient.archive_root / (entry['frame_object']['file_id'] + '.json')
            original = payload.read_bytes()
            altered = wire.decode_json(original)
            altered['frame'] = 'A' + altered['frame'][1:]
            payload.write_bytes(wire.canonical(altered))
            retained = recipient.path.read_bytes()
            with self.assertRaisesRegex(ValueError, 'frame bytes differ'):
                recipient.receive(bundle, carrier.id)
            self.assertEqual(recipient.path.read_bytes(), retained)


if __name__ == '__main__': unittest.main(verbosity=2)
