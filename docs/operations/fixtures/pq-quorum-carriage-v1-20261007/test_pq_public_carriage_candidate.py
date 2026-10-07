import hashlib
import itertools
import struct
import unittest
import pq_public_carriage_candidate as candidate


class PublicCarriageTests(unittest.TestCase):
    def test_exact_boundaries_and_all_arrival_orders_keep_original_bytes(self):
        for size in (1, 11999, 12000, 12001, 24000, 24001, 29679, 32768):
            raw = bytes(i % 251 for i in range(size))
            parts = candidate.split_public_bytes(raw)
            self.assertTrue(all(len(p) <= 12288 for p in parts))
            for order in itertools.permutations(parts):
                self.assertEqual(candidate.reassemble_public_bytes(order, hashlib.sha512(raw).digest()), raw)
        for value in (b'', b'0' * 32769, bytearray(b'0')):
            with self.assertRaises(ValueError):
                candidate.split_public_bytes(value)

    def test_incomplete_is_unavailable_and_inputs_remain_unchanged(self):
        raw = b'public' * 5000
        parts = candidate.split_public_bytes(raw)
        for count in (0, 1, 2):
            subset = parts[:count]
            with self.assertRaises(candidate.IncompletePublicCarriage):
                candidate.reassemble_public_bytes(subset, hashlib.sha512(raw).digest())
            self.assertEqual(subset, parts[:count])

    def test_duplicates_mixed_wholes_and_payload_tampering_refuse(self):
        raw = b'a' * 29679
        parts = candidate.split_public_bytes(raw)
        other = candidate.split_public_bytes(b'b' * 29679)
        corrupt = parts[-1][:-1] + b'z'
        for sequence in ((parts[0], parts[0], parts[2]), (parts[0], other[1], parts[2]),
                         (parts[0], parts[1], corrupt), (*parts, parts[0])):
            with self.assertRaises(ValueError):
                candidate.reassemble_public_bytes(sequence, hashlib.sha512(raw).digest())

    def test_authenticated_expected_root_cannot_be_learned_from_fragment(self):
        parts = candidate.split_public_bytes(b'a')
        for expected in (None, b'', b'0' * 64, bytearray(hashlib.sha512(b'a').digest())):
            with self.assertRaises(ValueError):
                candidate.reassemble_public_bytes(parts, expected)

    def test_malicious_headers_lengths_extra_bytes_and_unknown_version_refuse(self):
        parts = candidate.split_public_bytes(b'a' * 29679)
        prefix = candidate.DOMAIN
        digest = hashlib.sha512(b'a' * 29679).digest()
        payload = parts[0][len(prefix) + candidate.FIELDS.size:]
        cases = [parts[0][:-1], parts[0] + b'x', parts[0].replace(b'V1\0', b'V2\0', 1), b'x' * 12289]
        for total, count, index in ((0, 1, 0), (32769, 3, 0), (29679, 2, 0), (29679, 4, 0),
                                    (29679, 3, 3), (1, 3, 0), (29679, 0, 0)):
            cases.append(prefix + struct.pack('>IHH64s', total, count, index, digest) + payload)
        for packet in cases:
            with self.assertRaises(ValueError):
                candidate.parse_public_fragment(packet)


if __name__ == '__main__':
    unittest.main()
