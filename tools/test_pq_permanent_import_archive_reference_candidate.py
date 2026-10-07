"""Bounded public archive decoding; no signing or crypto process."""
import unittest
import pq_permanent_import_archive_reference_candidate as archive


class ArchiveWire(unittest.TestCase):
    def test_exact_complete_entries_and_rejected_alternate_lengths(self):
        record = bytes(32) + (3).to_bytes(4, 'big') + b'abc' + (2).to_bytes(4, 'big') + b'{}'
        raw = archive.DOMAIN + b'\0\1' + record
        self.assertEqual(archive.decode_archive(raw), [(bytes(32), b'abc', b'{}')])
        for changed in (raw[:-1], raw + b'\0', archive.DOMAIN + b'\0\0',
                        archive.DOMAIN + b'\0A' + record, b'x' * (archive.MAX_WIRE + 1)):
            with self.assertRaises(ValueError):
                archive.decode_archive(changed)

    def test_per_entry_and_aggregate_bounds_before_crypto(self):
        for pn, en in ((32769, 0), (0, 12289)):
            record = bytes(32) + pn.to_bytes(4, 'big') + b'x' * pn + en.to_bytes(4, 'big') + b'x' * en
            with self.assertRaises(ValueError):
                archive.decode_archive(archive.DOMAIN + b'\0\1' + record)
        record = bytes(32) + (32768).to_bytes(4, 'big') + b'x' * 32768 + (1).to_bytes(4, 'big') + b'x'
        with self.assertRaises(ValueError):
            archive.decode_archive(archive.DOMAIN + b'\0@' + record * 64)

    def test_independently_selected_anchor_types_and_limits(self):
        anchor = {'current_root': '01' * 64, 'key_count': 200001, 'next_nonce': 1,
                  'archive_head': '02' * 64, 'caller_locks_root': '03' * 64}
        self.assertEqual(archive.anchor(anchor), anchor)
        for key, value in (('key_count', 200002), ('key_count', True), ('next_nonce', True),
                           ('next_nonce', 1 << 64), ('current_root', '01' * 63)):
            changed = dict(anchor)
            changed[key] = value
            with self.assertRaises(ValueError):
                archive.anchor(changed)


if __name__ == '__main__':
    unittest.main()
