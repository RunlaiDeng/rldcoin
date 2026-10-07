"""Public Ed25519 admission counterexamples; no signing or crypto process."""
import unittest

from pq_authorization_candidate import prime_order_ed_point


class PublicPointAdmission(unittest.TestCase):
    def test_rfc8032_public_keys_and_basepoint(self):
        # RFC8032 section7.1 first three independently published public keys.
        for key in (
            'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
            '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
            'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
            '58' + '66' * 31,
        ):
            with self.subTest(key=key):
                self.assertTrue(prime_order_ed_point(bytes.fromhex(key)))

    def test_small_order_and_mixed_order_points(self):
        p = (1 << 255) - 19
        # Identity, order2 (0,-1), order4 (sqrt(-1),0), both signs.
        for y in (0, 1, p - 1):
            for sign in (0, 1):
                self.assertFalse(prime_order_ed_point((y | sign << 255).to_bytes(32, 'little')))
        # Basepoint plus order2: (-base_x,-base_y); not small-order, not prime.
        mixed_y = (-4 * pow(5, p - 2, p)) % p
        self.assertFalse(prime_order_ed_point((mixed_y | 1 << 255).to_bytes(32, 'little')))

    def test_reduced_noncanonical_encodings_and_width(self):
        p = (1 << 255) - 19
        for y in range(p, (1 << 255)):
            for sign in (0, 1):
                self.assertFalse(prime_order_ed_point((y | sign << 255).to_bytes(32, 'little')))
        for raw in (b'', bytes(31), bytes(33), bytearray(32), None):
            self.assertFalse(prime_order_ed_point(raw))


if __name__ == '__main__':
    unittest.main()
