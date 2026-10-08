"""Full signed ground preparation; discarded output never skips cold checks."""
import base64
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
from test_interstellar_receipt_scheduler import Fixture


class PreparationFrameTests(unittest.TestCase):
    def fixture(self):
        parent = Path(os.environ.get('RLD_RETAINED_GROUND_ROOT',
                      str(Path(__file__).resolve().parents[1] / 'tmp')))
        parent.mkdir(parents=True, exist_ok=True)
        root = Path(tempfile.mkdtemp(prefix='rld-preparation-frame-', dir=parent))
        # Keep every fresh no-value fixture, including failed publication residue.
        fixture = Fixture(root)
        frame = wire.make_frame('source-finality', '1' * 64, '3' * 64, '4' * 64,
                                wire.canonical({'synthetic_ground': True,
                                                'value_authority': False,
                                                'padding': 'x' * 174000}))
        with fixture.node(0) as node:
            for _ in range(8):
                node.enqueue_batch([(frame, fixture.ids[2])] * 4)
        return fixture

    def reset_witness(self):
        with mesh._verified_transits_lock:
            mesh._verified_transits.clear()

    def test_warm_preparation_preserves_complete_signed_bytes_without_decoding_discarded_frames(self):
        fixture = self.fixture()
        with fixture.node(0) as node:
            peer = fixture.ids[1]
            # Cold preparation first authenticates every original transit.
            self.reset_witness()
            with patch.object(mesh, '_transit_check', wraps=mesh._transit_check) as cold:
                node.exchange(peer)
            self.assertGreaterEqual(cold.call_count, len(node.state['messages']))
            raw = node.path.read_bytes()
            state = copy.deepcopy(node.state)
            original = mesh.transit_check

            def with_original_frame_output(*args, **kwargs):
                kwargs['include_frame'] = True
                return original(*args, **kwargs)

            decode = base64.b64decode
            with patch.object(mesh, 'transit_check', with_original_frame_output), \
                    patch.object(base64, 'b64decode', wraps=decode) as old_decode:
                expected = node.exchange(peer)
            self.assertGreaterEqual(old_decode.call_count, len(node.state['messages']))
            with patch.object(base64, 'b64decode', wraps=decode) as new_decode:
                actual = node.exchange(peer)
            self.assertEqual(new_decode.call_count, 0)
            self.assertEqual(wire.canonical(actual), wire.canonical(expected))
            self.assertEqual(len(actual['body']['transits']), mesh.MAX_PACKET_BATCH)
            self.assertLessEqual(len(wire.canonical(actual)), mesh.MAX_BATCH)
            self.assertEqual(node.state, state)
            self.assertEqual(node.path.read_bytes(), raw)
            self.assertFalse(node.receipts())

    def test_missing_witness_still_performs_every_original_full_frame_check(self):
        fixture = self.fixture()
        with fixture.node(0) as node, patch.object(mesh, 'MAX_VERIFIED_TRANSITS', 0):
            self.reset_witness()
            original = mesh.transit_check
            decode = base64.b64decode
            with patch.object(mesh, '_transit_check', wraps=mesh._transit_check) as full, \
                    patch.object(base64, 'b64decode', wraps=decode) as decoding:
                actual = node.exchange(fixture.ids[1])
            actual_checks, actual_decodes = full.call_count, decoding.call_count

            def with_original_frame_output(*args, **kwargs):
                kwargs['include_frame'] = True
                return original(*args, **kwargs)

            with patch.object(mesh, 'transit_check', with_original_frame_output), \
                    patch.object(mesh, '_transit_check', wraps=mesh._transit_check) as full, \
                    patch.object(base64, 'b64decode', wraps=decode) as decoding:
                expected = node.exchange(fixture.ids[1])
            self.assertGreaterEqual(actual_checks, len(node.state['messages']))
            self.assertGreater(actual_decodes, 0)
            self.assertEqual(actual_checks, full.call_count)
            self.assertEqual(actual_decodes, decoding.call_count)
            self.assertEqual(wire.canonical(actual), wire.canonical(expected))

    def test_later_changed_signature_refuses_after_warm_preparation_without_publication(self):
        fixture = self.fixture()
        with fixture.node(0) as node:
            node.exchange(fixture.ids[1])
            before = node.path.read_bytes()
            ident = node.state['recent_transits'][-1]
            node.state['messages'][ident]['packet']['signature'] = '0' * 128
            with self.assertRaisesRegex(ValueError, 'signature'):
                node.prepare_exchange(fixture.ids[1])
            self.assertEqual(node.path.read_bytes(), before)
            self.assertFalse(node.receipts())

    def test_failed_preparation_keeps_private_bytes_and_every_scheduling_position(self):
        fixture = self.fixture()
        with fixture.node(0) as node:
            node.exchange(fixture.ids[1])
            state = copy.deepcopy(node.state)
            before = node.path.read_bytes()
            with mesh._carriage_position_lock:
                positions = copy.deepcopy(mesh._carriage_positions)
            with patch.object(mesh, 'atomic', side_effect=OSError('publication refused')):
                with self.assertRaises(OSError):
                    node.prepare_exchange(fixture.ids[1])
            self.assertEqual(node.state, state)
            self.assertEqual(node.path.read_bytes(), before)
            with mesh._carriage_position_lock:
                self.assertEqual(mesh._carriage_positions, positions)


if __name__ == '__main__':
    unittest.main()
