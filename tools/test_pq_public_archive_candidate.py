import hashlib
import struct
import unittest

import pq_public_archive_candidate as archive
import pq_public_carriage_candidate as carriage


class PublicArchiveTests(unittest.TestCase):
    def test_full64_reverse_arrival_keeps_order_bytes_and_original_caps(self):
        entries = tuple(bytes([index]) * 32768 for index in range(64))
        manifest_parts, parts = archive.split_archive(entries)
        self.assertEqual(sum(map(len, entries)), 2097152)
        self.assertEqual(len(parts), 192)
        self.assertTrue(all(len(p) <= 12288 for p in (*manifest_parts, *parts)))
        expected = hashlib.sha512(archive.encode_manifest(entries)).digest()
        self.assertEqual(archive.reassemble_archive(manifest_parts[::-1], parts[::-1], expected), entries)

    def test_missing_manifest_or_tail_is_unavailable_without_input_changes(self):
        entries = (b'a' * 24707, b'b' * 24707)
        manifest, parts = archive.split_archive(entries)
        expected = hashlib.sha512(archive.encode_manifest(entries)).digest()
        before = (manifest, parts)
        for m, p in (((), parts), (manifest, parts[:-1]), (manifest, ())):
            with self.assertRaises(carriage.IncompletePublicCarriage):
                archive.reassemble_archive(m, p, expected)
        self.assertEqual((manifest, parts), before)

    def test_cross_archive_duplicate_tamper_or_wrong_independent_root_refuse(self):
        entries = (b'a' * 24707, b'b' * 24707)
        manifest, parts = archive.split_archive(entries)
        expected = hashlib.sha512(archive.encode_manifest(entries)).digest()
        foreign = carriage.split_public_bytes(b'c' * 24707)[0]
        for p in ((foreign, *parts[1:]), (parts[0], parts[0], *parts[2:]),
                  (*parts[:-1], parts[-1][:-1] + b'z')):
            with self.assertRaises(ValueError):
                archive.reassemble_archive(manifest, p, expected)
        for root in (None, b'', b'0' * 64):
            with self.assertRaises(ValueError):
                archive.reassemble_archive(manifest, parts, root)
        reversed_manifest = carriage.split_public_bytes(archive.encode_manifest(entries[::-1]))
        with self.assertRaises(ValueError):
            archive.reassemble_archive(reversed_manifest, parts, expected)

    def test_manifest_and_inventory_bounds_are_checked_before_complete_output(self):
        for entries in ([], [b''] , [b'a'] * 65, [b'a', b'a'], [b'a' * 32769], [bytearray(b'a')]):
            with self.assertRaises(ValueError):
                archive.encode_manifest(entries)
        valid = archive.encode_manifest((b'a',))
        bad = [valid + b'x', valid[:-1], valid.replace(b'V1\0', b'V2\0', 1),
               archive.DOMAIN + struct.pack('>H', 65),
               archive.DOMAIN + struct.pack('>H', 1) + archive.ENTRY.pack(32769, b'0' * 64),
               archive.DOMAIN + struct.pack('>H', 2) + archive.ENTRY.pack(1, b'0' * 64) * 2]
        for raw in bad:
            with self.assertRaises(ValueError):
                archive.decode_manifest(raw)
        manifest, parts = archive.split_archive((b'a',))
        expected = hashlib.sha512(valid).digest()
        with self.assertRaises(ValueError):
            archive.reassemble_archive(manifest, parts * 193, expected)


if __name__ == '__main__':
    unittest.main()
