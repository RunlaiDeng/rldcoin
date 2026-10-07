"""Candidate commitment adversarial transitions; no Native, signing or storage."""
from dataclasses import replace
import itertools
import unittest

import permanent_import_index_candidate as index
import pq_public_carriage_candidate as carriage


class PermanentImportIndexTests(unittest.TestCase):
    scope = bytes([1]) * 32 + bytes([2]) * 32

    def test_all_small_insertion_orders_have_same_root_and_proved_transitions(self):
        keys = tuple(n.to_bytes(32, 'big') for n in (0, 1, 15, 256, 1 << 255))
        roots = set()
        for order in itertools.permutations(keys):
            state = index.Index(self.scope)
            for key in order:
                expected = index.derive_insert_root(self.scope, state.root, key, state.proof(key))
                self.assertEqual(state.insert(key), expected)
                for old in order[:state.count]:
                    self.assertTrue(index.verify_key_proof(self.scope, state.root, old, state.proof(old)))
            roots.add(state.root)
        self.assertEqual(len(roots), 1)

    def test_duplicate_unknown_root_stale_proof_and_changed_scope_never_authorize_append(self):
        state = index.Index(self.scope)
        first, second = bytes(32), bytes([3]) * 32
        state.insert(first)
        old_root, old_proof = state.root, state.proof(second)
        state.insert(second)
        self.assertFalse(index.verify_key_proof(self.scope, old_root, second, old_proof))
        # Old authenticated root is not freshness: it cannot serve as the current root.
        with self.assertRaises(ValueError):
            index.derive_insert_root(self.scope, state.root, second, old_proof)
        before = state.root
        with self.assertRaises(ValueError):
            state.insert(first)
        self.assertEqual(state.root, before)
        with self.assertRaises(ValueError):
            index.derive_insert_root(self.scope, state.root, first, state.proof(first))
        for scope, root in ((self.scope, None), (self.scope, bytes(64)), (bytes(64), state.root)):
            with self.assertRaises(ValueError):
                index.verify_key_proof(scope, root, first, state.proof(first))

    def test_changed_siblings_counts_routes_and_noncanonical_wire_refuse(self):
        state = index.Index(self.scope)
        for n in range(16):
            state.insert(n.to_bytes(32, 'big'))
        key = bytes(32)
        proof = state.proof(key)
        frame = proof.frames[0]
        for altered in (replace(frame, sibling_hash=bytes(64)),
                        replace(frame, sibling_count=frame.sibling_count + 1),
                        replace(frame, common=bytes([255]) * 32), replace(frame, bit=True)):
            bad = replace(proof, frames=(altered, *proof.frames[1:]))
            with self.assertRaises(ValueError):
                index.verify_key_proof(self.scope, state.root, key, bad)
        raw = index.encode_proof(proof)
        self.assertEqual(index.decode_proof(raw), proof)
        for bad in (raw + b'x', raw[:-1], b'x' * 32769, raw[:len(index.PROOF_DOMAIN)] + b'\x02' + raw[len(index.PROOF_DOMAIN) + 1:]):
            with self.assertRaises(ValueError):
                index.decode_proof(bad)

    def test_real_full256_bit_path_stays_under_original_object_and_packet_bounds(self):
        state = index.Index(self.scope)
        state.insert(bytes(32))
        for bit in range(256):
            state.insert((1 << bit).to_bytes(32, 'big'))
        proof = state.proof(bytes(32))
        self.assertEqual(len(proof.frames), 256)
        raw = index.encode_proof(proof)
        self.assertLessEqual(len(raw), 32768)
        restored = index.decode_proof(raw)
        self.assertTrue(index.verify_key_proof(self.scope, state.root, bytes(32), restored))
        pieces = carriage.split_public_bytes(raw)
        self.assertEqual(len(pieces), 3)
        self.assertTrue(all(len(packet) <= 12288 for packet in pieces))
        import hashlib
        self.assertEqual(carriage.reassemble_public_bytes(list(reversed(pieces)), hashlib.sha512(raw).digest()), raw)


if __name__ == '__main__':
    unittest.main()
