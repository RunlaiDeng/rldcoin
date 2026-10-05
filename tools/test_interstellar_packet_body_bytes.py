"""Packet signature input bytes remain exact across fast and fallback paths."""
import base64
import copy
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import interstellar_frame_digest as streamed
import interstellar_mesh as mesh
import interstellar_transfer as wire


class PacketBodyBytesTests(unittest.TestCase):
    def test_every_ascii_escape_unicode_and_metadata_key_order(self):
        for frame in [chr(c) for c in range(128)] + ['', '中文', 'AA==', None, [], 12]:
            body = {'z': {'frame': 'lookalike'}, 'frame': frame, 'a': '\\"你好',
                    'frame!': [False, None], 'frame~': {'nested': '\n'}}
            self.assertEqual(streamed.packet_body_bytes(body), wire.canonical(body))
            self.assertEqual(streamed.packet_body_bytes(dict(reversed(list(body.items())))),
                             wire.canonical(body))
        for body in ({}, [], {'other': 'AA=='}, {1: 'x', 'frame': 'AA=='}):
            try: expected = wire.canonical(body)
            except (TypeError, ValueError) as error:
                with self.assertRaises(type(error)): streamed.packet_body_bytes(body)
            else: self.assertEqual(streamed.packet_body_bytes(body), expected)

    def test_large_bounded_frame_avoids_full_string_encoder_and_tighter_limit_falls_back(self):
        body = {'frame': base64.b64encode(b'ground' * 100000).decode(), 'a': 'metadata'}
        expected = wire.canonical(body); ordinary = wire.canonical
        def metadata_only(value):
            if value is body or value is body['frame']:
                raise AssertionError('large frame reencoded')
            return ordinary(value)
        with patch.object(wire, 'canonical', side_effect=metadata_only):
            self.assertEqual(streamed.packet_body_bytes(body), expected)
        with patch.object(wire, 'MAX_FRAME', 1), patch.object(wire, 'canonical', wraps=ordinary) as call:
            self.assertEqual(streamed.packet_body_bytes(body), expected)
            call.assert_called_once_with(body)

    def test_ordinary_signatures_verify_and_every_changed_field_still_refuses(self):
        key = Ed25519PrivateKey.generate(); network = 'a' * 64
        body = {'format': mesh.VERSION, 'network': network,
                'node_id': mesh.node_id(key.public_key().public_bytes_raw().hex()),
                'frame': 'AA==', 'nonce': 'b' * 64}
        signed = mesh.sign(key, 'packet', body)
        self.assertEqual(mesh.verify(signed, 'packet', network), body)
        for field, value in [('frame', 'AB=='), ('nonce', 'c' * 64)]:
            bad = copy.deepcopy(signed); bad['body'][field] = value
            with self.assertRaisesRegex(ValueError, 'signature'): mesh.verify(bad, 'packet', network)
        with self.assertRaisesRegex(ValueError, 'signature'): mesh.verify(signed, 'hop', network)
        with self.assertRaisesRegex(ValueError, 'network'): mesh.verify(signed, 'packet', 'c' * 64)


if __name__ == '__main__':
    unittest.main()
