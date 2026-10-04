"""Exact raw-state admission refuses malformed, oversized and forged evidence."""
import copy
import tempfile
import unittest
from unittest.mock import patch

import interstellar_active_state as codec
import interstellar_mesh as mesh
import interstellar_transfer as wire
from test_interstellar_mesh import Fixture


class StateDecodeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.f=Fixture(self.temp.name)
        with self.f.node('earth') as node:
            self.ident=node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id'])
            self.state=copy.deepcopy(node.state);self.path=node.path
        self.raw=self.path.read_bytes()

    def decode(self, raw, **changes):
        limits=dict(network=self.state['network'],node_id=self.state['node_id'],
                    max_state=mesh.MAX_STATE,max_messages=mesh.MAX_MESSAGES,max_transit=mesh.MAX_BATCH)
        limits.update(changes)
        return codec.decode(raw,**limits)

    def test_full_raw_roundtrip_and_exact_capacity_without_a_supplied_size(self):
        self.assertEqual(self.decode(self.raw,max_state=len(self.raw)),self.state)
        self.assertEqual(self.decode(self.raw),mesh.unpack_state_storage(wire.decode_json(self.raw),
                                                                        self.state['network'],self.state['node_id']))
        with patch.object(wire,'decode_json',side_effect=AssertionError('oversized raw must not decode')):
            with self.assertRaisesRegex(ValueError,'capacity'):
                self.decode(self.raw,max_state=len(self.raw)-1)

    def test_changed_encoding_duplicate_fields_and_wrong_identity_refuse(self):
        for raw in (self.raw+b'\n',b'{"format":1,"format":2}',b'[]'):
            with self.subTest(raw_size=len(raw)),self.assertRaises(ValueError):self.decode(raw)
        for change in ({'network':'f'*64},{'node_id':'f'*64}):
            with self.subTest(change=change),self.assertRaisesRegex(ValueError,'ownership'):
                self.decode(self.raw,**change)

    def test_complete_object_digest_and_expanded_capacity_still_refuse(self):
        image=wire.decode_json(self.raw)
        altered=copy.deepcopy(image);entry=next(iter(altered['state']['messages'].values()))
        entry['transit']['routing']['signature']='0'*128
        with self.assertRaisesRegex(ValueError,'complete bytes'):
            self.decode(wire.canonical(altered))
        entry=next(iter(image['state']['messages'].values()))
        with self.assertRaisesRegex(ValueError,'expanded'):
            self.decode(self.raw,max_transit=entry['expanded_size_bytes']-1)

    def test_recomputed_storage_hash_does_not_authorize_an_invalid_signed_packet(self):
        state=copy.deepcopy(self.state);transit=state['messages'].pop(self.ident)
        transit['packet']['body']['nonce']='f'*64
        ident=mesh.digest(transit['packet']);state['messages'][ident]=transit;state['recent_transits']=[ident]
        image=mesh.pack_state_storage(state);raw=wire.canonical(image)
        self.assertEqual(self.decode(raw),state)  # Storage is not signature authority.
        self.path.write_bytes(raw)
        with mesh._verified_transits_lock:mesh._verified_transits.clear()
        with self.assertRaisesRegex(ValueError,'signature'):self.f.node('earth')
        self.assertEqual(self.path.read_bytes(),raw)


if __name__=='__main__':unittest.main()
