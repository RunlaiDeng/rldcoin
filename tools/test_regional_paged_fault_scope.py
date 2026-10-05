import dataclasses
import tempfile
import unittest
from pathlib import Path

from regional_paged_fault_scope import ReplicaPin, Scope, document, raw


KEYS = tuple(f'{i:064x}' for i in range(1, 5))


def scope(height, cap=24, keys=KEYS):
    replicas = tuple(ReplicaPin('earth', n, height, 'a'*64, 'b'*64, key, 'c'*64)
                     for n, key in enumerate(keys))
    return Scope('d'*64, replicas, (('earth', cap),))


class Tests(unittest.TestCase):
    def test_all_parent_residues_and_real_successor(self):
        for height in range(24):
            for index, key in enumerate(KEYS):
                expected = height + ((index - height) % 4) + 1
                if expected <= 24:
                    self.assertEqual(scope(height).missing_leader_gate('earth', key), expected)
                    self.assertGreater(expected, height)
                    self.assertEqual(KEYS[(expected - 1) % 4], key)
                else:
                    with self.assertRaises(ValueError):
                        scope(height).missing_leader_gate('earth', key)

    def test_actual_current_heights_do_not_use_legacy_gate(self):
        self.assertEqual(scope(9, 27).missing_leader_gate('earth', KEYS[0]), 13)
        self.assertEqual(scope(6).missing_leader_gate('earth', KEYS[0]), 9)
        self.assertEqual(scope(8).missing_leader_gate('earth', KEYS[0]), 9)
        self.assertNotEqual(scope(9, 27).missing_leader_gate('earth', KEYS[0]),
                            scope(7).missing_leader_gate('earth', KEYS[0]))

    def test_unknown_unordered_duplicate_membership_and_height_refuse(self):
        for value in (scope(9, keys=KEYS[::-1]), scope(9, keys=(KEYS[0],)*4),
                      scope(True), scope(-1), scope(24),
                      dataclasses.replace(scope(9), replicas=scope(9).replicas[:3]),
                      dataclasses.replace(scope(9), replicas=(
                          dataclasses.replace(scope(9).replicas[0], height=8),
                          *scope(9).replicas[1:]))):
            with self.assertRaises(ValueError):
                value.missing_leader_gate('earth', KEYS[0])
        with self.assertRaises(ValueError):
            scope(9).missing_leader_gate('earth', 'e'*64)
        with self.assertRaises(ValueError):
            scope(9).missing_leader_gate('proxima', KEYS[0])

    def test_scope_is_immutable_and_observation_grants_no_rights(self):
        value = scope(9)
        self.assertFalse(value.native_authority)
        self.assertFalse(value.independent_freshness)
        self.assertEqual((value.stage_seconds, value.round_seconds, value.max_new_heights,
                          value.maturity, value.quorum), (600, 60, 24, 2, 3))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            value.quorum = 2

    def test_strict_bounded_file_decoder_and_symlink(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch).resolve() / 'observation.json'
            path.write_bytes(b'{"height":9,"height":7}')
            with self.assertRaises(ValueError):
                document(path)
            with self.assertRaises(ValueError):
                raw(path, 1)
            with self.assertRaises(ValueError):
                document(path, '0'*64)
            path.write_bytes(b'{"height":9}')
            self.assertEqual(document(path), {'height': 9})
            link = path.parent / 'link'
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                document(link)


if __name__ == '__main__':
    unittest.main()
