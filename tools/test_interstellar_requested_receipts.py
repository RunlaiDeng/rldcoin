"""Fresh opaque transport fixtures; signed inventory selects carriage only."""
import unittest
import copy
from unittest.mock import patch

import interstellar_mesh as mesh
from test_interstellar_receipt_scheduler import Fixture
import tempfile


class RequestedReceiptTests(unittest.TestCase):
    def fixture(self, count=64):
        temporary = tempfile.TemporaryDirectory(prefix='requested-receipt-')
        self.addCleanup(temporary.cleanup)
        return Fixture(temporary.name, count=count)

    def request(self, fixture, ids, peer_number=1):
        with fixture.node(peer_number) as peer, fixture.node(0) as carrier:
            carrier.state['peer_inventory'][peer.id] = mesh.sign(peer.key, 'inventory',
                dict(format=mesh.VERSION, network=carrier.network, node_id=peer.id, packet_ids=sorted(ids)))
            carrier.save()

    def test_current_signed_inventory_request_gets_a_slot_without_excluding_history(self):
        with tempfile.TemporaryDirectory(prefix='requested-receipt-') as temporary:
            fixture = Fixture(temporary, count=64)
            requested = sorted(fixture.receipt_ids)[-1]
            with fixture.node(1) as peer, fixture.node(0) as carrier:
                carrier.state['peer_inventory'][peer.id] = mesh.sign(peer.key, 'inventory',
                    dict(format=mesh.VERSION, network=carrier.network, node_id=peer.id, packet_ids=[requested]))
                carrier.save()
                before = carrier.path.read_bytes()
                bundle = carrier.exchange(peer.id)
                selected = [mesh.receipt_check(r, carrier.network) for r in bundle['body']['receipts']]
                self.assertIn(requested, selected)
                self.assertEqual(len(selected), 16)
                self.assertEqual(len(set(selected)), 16)
                self.assertTrue(set(selected)-{requested})
                self.assertEqual(carrier.path.read_bytes(), before)

    def test_two_classes_fully_rotate_with_independent_durable_actual_counts(self):
        fixture = self.fixture()
        wanted = set(sorted(fixture.receipt_ids)[32:])
        self.request(fixture, wanted)
        seen = set()
        for _ in range(4):
            with fixture.node(0) as carrier:
                bundle = carrier.prepare_exchange(fixture.ids[1])
                ids = {mesh.receipt_check(r, carrier.network) for r in bundle['body']['receipts']}
                self.assertEqual(len(ids & wanted), 8)
                self.assertEqual(len(ids-wanted), 8)
                seen.update(ids)
                cursors = copy.deepcopy((carrier.state['receipt_cursors'], carrier.state['requested_receipt_cursors']))
                carrier.tick()
                self.assertEqual(cursors, (carrier.state['receipt_cursors'], carrier.state['requested_receipt_cursors']))
        self.assertEqual(seen, fixture.receipt_ids)
        with fixture.node(0) as carrier:
            self.assertEqual(carrier.state['receipt_cursors'][fixture.ids[1]], 32)
            self.assertEqual(carrier.state['requested_receipt_cursors'][fixture.ids[1]], 32)
            self.assertEqual(set(carrier.receipts()), fixture.receipt_ids)
            self.assertFalse(carrier.status()['payment_authorized'])

    def test_other_peer_and_public_construction_cannot_advance_requested_cursor(self):
        fixture = self.fixture()
        self.request(fixture, sorted(fixture.receipt_ids)[32:])
        with fixture.node(0) as carrier:
            before = copy.deepcopy(carrier.state['requested_receipt_cursors'])
            carrier.exchange(fixture.ids[1])
            carrier.prepare_exchange(fixture.ids[2])
            self.assertEqual(carrier.state['requested_receipt_cursors'], before)
            carrier.prepare_exchange(fixture.ids[1])
            self.assertEqual(carrier.state['requested_receipt_cursors'][fixture.ids[1]], 8)
            self.assertEqual(carrier.state['receipt_cursors'][fixture.ids[1]], 8)
            self.assertEqual(carrier.state['receipt_cursors'][fixture.ids[2]], 16)

    def test_publication_and_capacity_refusal_leave_both_cursors_and_all_evidence(self):
        for boundary in ('write', 'capacity'):
            fixture = self.fixture()
            self.request(fixture, sorted(fixture.receipt_ids)[32:])
            with fixture.node(0) as carrier:
                before = carrier.path.read_bytes()
                state = copy.deepcopy(carrier.state)
                injected = patch.object(mesh, 'atomic', side_effect=OSError('requested cursor publication')) if boundary == 'write' else patch.object(mesh, 'MAX_STATE', 1)
                with injected:
                    with self.assertRaises((OSError, ValueError)):
                        carrier.prepare_exchange(fixture.ids[1])
                self.assertEqual(carrier.path.read_bytes(), before)
                self.assertEqual(carrier.state, state)
                self.assertEqual(set(carrier.receipts()), fixture.receipt_ids)

    def test_single_receipt_wire_budget_rotates_classes_without_extra_slots(self):
        fixture = self.fixture()
        self.request(fixture, sorted(fixture.receipt_ids)[32:])
        with fixture.node(0) as carrier:
            baseline = carrier.exchange(fixture.ids[1])
            body = dict(baseline['body'], receipts=baseline['body']['receipts'][:1])
            limit = len(mesh.evidence.canonical(body))+512
            wanted = set(sorted(fixture.receipt_ids)[32:])
            classes = []
            with patch.object(mesh, 'MAX_BATCH', limit):
                for _ in range(6):
                    bundle = carrier.prepare_exchange(fixture.ids[1])
                    self.assertEqual(len(bundle['body']['receipts']), 1)
                    ident = mesh.receipt_check(bundle['body']['receipts'][0], carrier.network)
                    classes.append(ident in wanted)
            self.assertEqual(classes, [True, False, True, False, True, False])
            self.assertEqual(carrier.state['receipt_cursors'][fixture.ids[1]], 3)
            self.assertEqual(carrier.state['requested_receipt_cursors'][fixture.ids[1]], 3)

    def test_forged_v2_marker_and_legacy_state_refuse_without_rewrite(self):
        fixture = self.fixture()
        path = fixture.root/'0'/'mesh-state.json'
        value = mesh.evidence.decode_json(path.read_bytes())
        value['state'].pop('requested_receipt_cursors')
        path.write_bytes(mesh.evidence.canonical(value))
        before = path.read_bytes()
        with self.assertRaises(ValueError): fixture.node(0)
        self.assertEqual(path.read_bytes(), before)

    def test_v1_identity_marker_refuses_without_state_or_identity_rewrite(self):
        fixture = self.fixture()
        path = fixture.root/'0'/'identity.private.json'
        value = mesh.load(path, 8192)
        value['receipt_scheduler'] = 'RLD-CONTACT-RECEIPT-SCHEDULER-V1'
        mesh.atomic(path, value)
        before = path.read_bytes()
        state = (fixture.root/'0'/'mesh-state.json').read_bytes()
        with self.assertRaises(ValueError): fixture.node(0)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual((fixture.root/'0'/'mesh-state.json').read_bytes(), state)

    def test_requested_cursor_wrap_and_malformed_request_cursors(self):
        fixture = self.fixture()
        self.request(fixture, sorted(fixture.receipt_ids)[32:])
        with fixture.node(0) as carrier:
            peer = fixture.ids[1]
            carrier.state['receipt_cursors'][peer] = 2**63-1
            carrier.state['requested_receipt_cursors'][peer] = 2**63-1
            carrier.save()
            carrier.prepare_exchange(peer)
            self.assertEqual(carrier.state['requested_receipt_cursors'][peer], 7)
            self.assertEqual(carrier.state['receipt_cursors'][peer], 7)
        path = fixture.root/'0'/'mesh-state.json'
        valid = path.read_bytes()
        for malformed in (-1, True, 2**63, '0'):
            value = mesh.evidence.decode_json(valid)
            value['state']['requested_receipt_cursors'][peer] = malformed
            path.write_bytes(mesh.evidence.canonical(value))
            before = path.read_bytes()
            with self.assertRaises(ValueError): fixture.node(0)
            self.assertEqual(path.read_bytes(), before)
        path.write_bytes(valid)


if __name__ == '__main__':
    unittest.main()
