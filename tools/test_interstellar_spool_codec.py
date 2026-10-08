"""Lossless ground carriage preserves signed bytes, limits and custody refusal."""
import copy
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

import interstellar_mesh as mesh
import interstellar_spool_codec as codec
import interstellar_transfer as wire
from test_interstellar_mesh import Fixture as MeshFixture


class SpoolCodecTests(unittest.TestCase):
    def test_exact_roundtrip_binary_and_original_limit(self):
        for raw in (bytes(range(256)) * 512, b'{"complete_signed_bytes":' + b'0' * 500000 + b'}'):
            encoded = codec.encode(raw, limit=len(raw))
            self.assertLess(len(encoded), len(raw))
            self.assertEqual(codec.decode(encoded, limit=len(raw)), raw)
            with self.assertRaises(ValueError):codec.encode(raw, limit=len(raw) - 1)
            with self.assertRaises(ValueError):codec.decode(encoded, limit=len(raw) - 1)
        with self.assertRaises(ValueError):codec.encode(b'x', limit=1)
        for raw in (b'', bytearray(b'x')):
            with self.assertRaises(ValueError):codec.encode(raw, limit=1000)

    def test_truncation_trailing_concatenation_damage_and_dictionary_refuse(self):
        raw = b'exact-complete-bytes' * 100
        encoded = codec.encode(raw, limit=4096)
        dictionary = zlib.compressobj(zdict=b'exact-complete-bytes')
        with_dictionary = encoded[:codec.HEADER_SIZE] + dictionary.compress(raw) + dictionary.flush()
        damaged = bytearray(encoded);damaged[-1] ^= 1
        for data in (encoded[:10], encoded[:-1], encoded + b'\0', encoded + zlib.compress(b'other'),
                     bytes(damaged), with_dictionary, raw):
            with self.subTest(size=len(data)):
                with self.assertRaises(ValueError):codec.decode(data, limit=4096)

    def test_false_length_digest_encoded_capacity_and_bomb_refuse(self):
        raw = b'zero' * 1000
        encoded = codec.encode(raw, limit=len(raw))
        for size in (0, len(raw) - 1, len(raw) + 1, 2**64 - 1):
            wrong = codec.MAGIC + struct.pack('>Q', size) + encoded[len(codec.MAGIC) + 8:]
            with self.assertRaises(ValueError):codec.decode(wrong, limit=len(raw))
        wrong = encoded[:len(codec.MAGIC) + 8] + bytes(32) + encoded[codec.HEADER_SIZE:]
        with self.assertRaises(ValueError):codec.decode(wrong, limit=len(raw))
        with self.assertRaises(ValueError):codec.decode(encoded, limit=len(encoded) - 1)
        # Output is capped at the declared length plus one, even though the
        # otherwise valid stream would expand far beyond that declaration.
        bomb = codec.MAGIC + struct.pack('>Q', 32) + hashlib.sha256(b'x'*32).digest() + zlib.compress(b'x' * 1000000)
        with self.assertRaises(ValueError):codec.decode(bomb, limit=4096)

    def fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix='rld-lossless-spool-')
        self.addCleanup(temporary.cleanup)
        fixture = MeshFixture(temporary.name)
        for config in fixture.configs.values():
            for contact in config['contacts']:contact['adapter'] = codec.FORMAT
        return fixture

    def test_multihop_restart_preserves_frame_and_receipt_checks(self):
        fixture = self.fixture();fixture.rounds()
        with fixture.node('earth') as node:
            ident = node.enqueue(fixture.frame(), fixture.identities['andromeda']['node_id'])
        fixture.rounds(8)
        with fixture.node('andromeda') as node:
            self.assertIn(ident, node.receipts())
            self.assertEqual(mesh.transit_check(node.transit(ident), node.network)[1], fixture.frame())
            self.assertFalse(node.status()['payment_authorized'])
        with fixture.node('earth') as node:self.assertIn(ident, node.receipts())

    def test_original_exchange_bytes_and_logical_spool_accounting(self):
        fixture = self.fixture();fixture.rounds()
        peer = fixture.identities['proxima']['node_id']
        with fixture.node('earth') as node:
            node.enqueue(wire.make_frame('source-finality', '1'*64, '3'*64, '4'*64, b'0' * 100000), peer)
            bundle = node.prepare_exchange(peer);raw = wire.canonical(bundle)
            with patch.object(node, 'prepare_exchange', return_value=bundle):
                node._send_spool(peer, node.contacts[peer])
            path = node.contacts[peer]['outbox'] / (mesh.digest(bundle) + '.json')
            self.assertEqual(codec.decode(path.read_bytes(), limit=mesh.MAX_BATCH), raw)
            paths, total = mesh.spool_files(path.parent, codec.FORMAT)
            self.assertIn(path, paths);self.assertGreaterEqual(total, len(raw))
            # Shrunk physical bytes never create extra logical capacity.
            with patch.object(mesh, 'MAX_SPOOL_BYTES', len(raw) - 1):
                with self.assertRaises(ValueError):mesh.spool_files(path.parent, codec.FORMAT)

    def test_bad_stream_signature_and_durable_failure_retain_exact_input(self):
        fixture = self.fixture();fixture.rounds()
        peer = fixture.identities['proxima']['node_id']
        directory = Path(fixture.configs['proxima']['contacts'][0]['inbox'])
        for mode in ('stream', 'signature', 'publication'):
            with fixture.node('earth') as node:
                frame = wire.make_frame('source-finality', '1'*64, '3'*64, '4'*64, mode.encode())
                node.enqueue(frame, peer);bundle = node.prepare_exchange(peer)
            value = copy.deepcopy(bundle)
            if mode == 'signature':value['signature'] = '0' * 128
            raw = codec.encode(wire.canonical(value), limit=mesh.MAX_BATCH)
            if mode == 'stream':raw += b'trailing'
            path = directory / (mesh.digest(value) + '.json');wire.write_new(path, raw)
            with fixture.node('proxima') as node:
                before = copy.deepcopy({k:node.state[k] for k in ('adverts', 'messages', 'receipts')})
                receive = node.receive
                def failing(value, peer):
                    with patch.object(mesh, 'atomic', side_effect=OSError('durable refused')):
                        return receive(value, peer)
                if mode == 'publication':
                    with patch.object(node, 'receive', side_effect=failing):result = node.tick()
                else:result = node.tick()
                self.assertTrue(result['errors'])
                self.assertEqual(path.read_bytes(), raw)
                self.assertEqual({k:node.state[k] for k in before}, before)
            path.unlink()

    def test_explicit_interoperability_boundary_keeps_mismatched_input(self):
        fixture = self.fixture();fixture.rounds()
        peer = fixture.identities['proxima']['node_id']
        with fixture.node('earth') as node:bundle = node.prepare_exchange(peer)
        directory = Path(fixture.configs['proxima']['contacts'][0]['inbox'])
        path = directory / (mesh.digest(bundle) + '.json')
        for compressed in (False, True):
            config = copy.deepcopy(fixture.configs['proxima'])
            if compressed:config['contacts'][0].pop('adapter')
            raw = wire.canonical(bundle)
            if compressed:raw = codec.encode(raw, limit=mesh.MAX_BATCH)
            wire.write_new(path, raw)
            with mesh.Node(config) as node:
                result = node.tick();self.assertTrue(result['errors'])
                self.assertEqual(path.read_bytes(), raw)
            path.unlink()


if __name__ == '__main__':
    unittest.main()
