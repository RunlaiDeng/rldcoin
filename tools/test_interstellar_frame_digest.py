"""Complete commitments agree with ordinary wire bytes, including hostile metadata."""
import base64
import copy
import hashlib
import tempfile
import unittest
from unittest.mock import patch

import interstellar_active_state as codec
import interstellar_frame_digest as streamed
import interstellar_mesh as mesh
import interstellar_transfer as wire
from test_interstellar_mesh import Fixture


class FrameDigestTests(unittest.TestCase):
    def assert_exact(self, value):
        raw = wire.canonical(value)
        self.assertEqual(streamed.commitment(value), (hashlib.sha256(raw).hexdigest(), len(raw)))

    def test_all_key_positions_unicode_escapes_and_frame_lookalikes_stay_exact(self):
        for frame in ('', 'AA==', 'YWJj', base64.b64encode(bytes(range(256))).decode()):
            value = {'routing': {'frame': '', 'quote': '\\"你好'},
                'packet': {'signature': 'f' * 128, 'body': {'z': {'frame': ''}, 'frame': frame,
                    'a': '\u2603', 'frame!': 'not the frame', 'frame~': '\\'}, 'A': [1, True, None]},
                'hops': [{'frame': '', 'nested': {'frame': 'AA=='}}]}
            self.assert_exact(value)
            self.assert_exact(dict(reversed(list(value.items()))))

    def test_unsupported_shape_and_escaped_frame_use_complete_canonical_bytes(self):
        for value in ({}, [], {'packet': []}, {'packet': {'body': {'frame': '\\"'}}},
                      {'packet': {'body': {'frame': '中文'}}}, {'packet': {'body': {'frame': 12}}}):
            with self.subTest(value=value):self.assert_exact(value)

    def test_every_ascii_character_matches_wire_escaping_including_control_and_del(self):
        for code in range(128):
            with self.subTest(code=code):
                self.assert_exact({'packet': {'body': {'frame': 'AA'+chr(code)+'BB'}},
                                   'hops': [], 'routing': {}})

    def test_large_shared_frame_is_fully_bound_without_json_reserializing_its_string(self):
        value = {'packet': {'body': {'frame': base64.b64encode(b'ground payload' * 75000).decode(),
                                    'destination': 'a' * 64}}, 'hops': [], 'routing': {'signature': 'b' * 128}}
        raw = wire.canonical(value);expected=(hashlib.sha256(raw).hexdigest(),len(raw));canonical=wire.canonical
        def metadata_only(obj):
            if obj is value or obj is value['packet'] or obj is value['packet']['body'] or obj is value['packet']['body']['frame']:
                raise AssertionError('complete frame JSON serialization repeated')
            return canonical(obj)
        with patch.object(wire,'canonical',side_effect=metadata_only):self.assertEqual(streamed.commitment(value),expected)
        changed=copy.deepcopy(value);changed['packet']['body']['frame']=changed['packet']['body']['frame'][:-4]+'AAAA'
        self.assertNotEqual(streamed.commitment(changed)[0],expected[0]);self.assert_exact(changed)

    def test_changed_hop_route_and_packet_fields_always_change_the_complete_commitment(self):
        value={'packet': {'body': {'frame': 'YWJj', 'nonce': 'a'*64}}, 'routing': {'signature': 'b'*128}, 'hops': []}
        expected=streamed.commitment(value)
        for mutation in (lambda v:v['packet']['body'].update(nonce='c'*64),
                         lambda v:v['routing'].update(signature='c'*128),
                         lambda v:v['hops'].append({'to':'c'*64})):
            changed=copy.deepcopy(value);mutation(changed);self.assertNotEqual(streamed.commitment(changed),expected);self.assert_exact(changed)

    def test_signed_packet_ids_match_complete_canonical_bytes_and_reject_mutation(self):
        for value in ({}, [], {'body': []}, {'body': {'frame': 12}},
                      {'body': {'frame': '中文'}}, {'body': {'frame': '\\"'}},
                      *({'body': {'frame': 'AA'+chr(code)+'BB', 'z': '\\你好',
                                  'frame!': [1, True, None]},
                         'public_key': 'a'*64, 'signature': 'b'*128} for code in range(128))):
            with self.subTest(value=value):
                raw=wire.canonical(value)
                self.assertEqual(streamed.packet_commitment(value),
                                 (hashlib.sha256(raw).hexdigest(),len(raw)))
                self.assertEqual(mesh.digest(value),hashlib.sha256(raw).hexdigest())
        packet={'body': {'frame': base64.b64encode(b'public ground frame'*60000).decode(),
                         'nonce': 'a'*64}, 'public_key': 'b'*64, 'signature': 'c'*128}
        raw=wire.canonical(packet);expected=hashlib.sha256(raw).hexdigest();canonical=wire.canonical
        def metadata_only(obj):
            if obj is packet or obj is packet['body'] or obj is packet['body']['frame']:
                raise AssertionError('complete packet frame serialized again')
            return canonical(obj)
        with patch.object(wire,'canonical',side_effect=metadata_only):
            self.assertEqual(mesh.digest(packet),expected)
        for field in ('signature','public_key'):
            changed=copy.deepcopy(packet);changed[field]='d'*len(packet[field])
            self.assertNotEqual(mesh.digest(changed),expected)
        changed=copy.deepcopy(packet);changed['body']['frame']=changed['body']['frame'][:-4]+'AAAA'
        self.assertNotEqual(mesh.digest(changed),expected)

    def test_existing_storage_bytes_and_native_signature_boundary_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture=Fixture(directory)
            with fixture.node('earth') as node:
                ident=node.enqueue(fixture.frame(),fixture.identities['andromeda']['node_id']);state=copy.deepcopy(node.state);path=node.path
            image=wire.decode_json(path.read_bytes());entry=image['state']['messages'][ident]
            raw=wire.canonical(state['messages'][ident]);self.assertEqual(entry['expanded_sha256'],hashlib.sha256(raw).hexdigest());self.assertEqual(entry['expanded_size_bytes'],len(raw))
            self.assertEqual(codec.decode(path.read_bytes(),network=state['network'],node_id=state['node_id'],max_state=mesh.MAX_STATE,max_messages=mesh.MAX_MESSAGES,max_transit=mesh.MAX_BATCH),state)
            bad=copy.deepcopy(state);bad['messages'][ident]['packet']['signature']='0'*128;mesh.atomic(path,bad);retained=path.read_bytes()
            with mesh._verified_transits_lock:mesh._verified_transits.clear()
            with self.assertRaisesRegex(ValueError,'signature'):fixture.node('earth')
            self.assertEqual(path.read_bytes(),retained)


if __name__=='__main__':unittest.main()
