"""Exact SHA256 arithmetic reuse never authenticates a packet or Native value."""
import copy
import hashlib
import tempfile
import threading
import unittest
from unittest.mock import patch
import interstellar_frame_digest as hashing
import interstellar_mesh as mesh
import interstellar_transfer as wire
from test_interstellar_mesh import Fixture


class HashOperationTests(unittest.TestCase):
    def value(self):
        return {'packet':{'body':{'destination':'a'*64,'frame':'YWJj'*1024,
                    'nonce':'b'*64},'signature':'c'*128},
                'routing':{'signature':'d'*128},'hops':[]}

    def exact(self,value):
        raw=wire.canonical(value)
        self.assertEqual(hashing.commitment(value),(hashlib.sha256(raw).hexdigest(),len(raw)))

    def test_same_prefix_reuses_only_arithmetic_and_all_other_fields_still_bind(self):
        value=self.value()
        with hashing.hashing_operation():
            self.exact(value);witness=hashing._operation.get();prefix=next(iter(witness.prefixes.values()))
            for mutate in (lambda v:v['packet']['body'].update(nonce='e'*64),
                           lambda v:v['packet'].update(signature='e'*128),
                           lambda v:v['routing'].update(signature='e'*128)):
                changed=copy.deepcopy(value);mutate(changed);self.exact(changed)
                self.assertIs(next(iter(witness.prefixes.values())),prefix)
                self.assertNotEqual(hashing.commitment(value),hashing.commitment(changed))
            for mutate in (lambda v:v['packet']['body'].update(frame='YWJk'*1024),
                           lambda v:v['packet']['body'].update(destination='e'*64),
                           lambda v:v['hops'].append({'to':'e'*64})):
                changed=copy.deepcopy(value);mutate(changed);self.exact(changed)
        self.assertIsNone(hashing._operation.get());self.assertFalse(witness.frames or witness.prefixes)

    def test_every_ascii_escape_unicode_and_unsupported_shape_matches_full_encoder(self):
        with hashing.hashing_operation():
            for code in range(128):
                self.exact({'packet':{'body':{'frame':'A'+chr(code)+'B'}}})
            for value in ({},[],{'packet':[]},{'packet':{'body':{'frame':'中文'}}},
                          {'packet':{'body':{'frame':12}}}):self.exact(value)

    def test_count_bytes_and_prefix_capacity_fallback_preserves_commitments(self):
        for limits in ({'MAX_PREFIX_WITNESS_BYTES':1},
                       {'MAX_PREFIX_WITNESS_BYTES':4400},
                       {'MAX_PREFIX_WITNESS_ENTRIES':0},
                       {'MAX_PREFIX_WITNESS_ENTRIES':1},
                       {'MAX_PREFIX_LEFT_BYTES':1}):
            with patch.multiple(hashing,**limits),hashing.hashing_operation():
                for frame in ('YWJj'*1024,'YWJk'*1024):
                    value=self.value();value['packet']['body']['frame']=frame;self.exact(value)
                witness=hashing._operation.get()
                if witness is not None:
                    self.assertLessEqual(witness.retained_bytes,hashing.MAX_PREFIX_WITNESS_BYTES)
                    self.assertLessEqual(len(witness.frames),hashing.MAX_PREFIX_WITNESS_ENTRIES)
                    self.assertLessEqual(len(witness.prefixes),hashing.MAX_PREFIX_WITNESS_ENTRIES)
        with hashing.hashing_operation():
            self.exact(self.value());witness=hashing._operation.get()
            with patch.object(hashing,'MAX_PREFIX_WITNESS_BYTES',1):self.exact(self.value())
            self.assertFalse(witness.frames or witness.prefixes)

    def test_nested_and_failed_operations_discard_witness_and_release_nonblocking_owner(self):
        with self.assertRaisesRegex(OSError,'publication'):
            with hashing.hashing_operation():
                self.exact(self.value());witness=hashing._operation.get()
                with hashing.hashing_operation():self.assertIs(hashing._operation.get(),witness)
                raise OSError('publication refused')
        self.assertIsNone(hashing._operation.get());self.assertFalse(witness.frames or witness.prefixes)
        with hashing.hashing_operation():self.assertIsNotNone(hashing._operation.get())

    def test_parallel_owner_falls_back_without_wait_or_another_witness(self):
        outcome=[]
        def other():
            with hashing.hashing_operation():
                outcome.append(hashing._operation.get());self.exact(self.value())
        with hashing.hashing_operation():
            worker=threading.Thread(target=other);worker.start();worker.join(2)
            self.assertFalse(worker.is_alive());self.assertEqual(outcome,[None])

    def test_actual_preparation_and_cold_signature_refusal_keep_original_boundary(self):
        with tempfile.TemporaryDirectory() as root:
            fixture=Fixture(root);peer=fixture.identities['proxima']['node_id']
            with fixture.node('earth') as node:
                ident=node.enqueue(fixture.frame(),peer)
                node.prepare_exchange(peer)
                self.assertIsNone(hashing._operation.get())
                altered=copy.deepcopy(node.state['messages'][ident])
                altered['packet']['signature']='0'*128
                with hashing.hashing_operation():
                    self.exact(altered)
                    with self.assertRaisesRegex(ValueError,'signature'):
                        mesh.transit_check(altered,node.network)
            with mesh._verified_transits_lock:mesh._verified_transits.clear()
            with fixture.node('earth') as node:
                self.assertIn(ident,node.state['messages'])
                with self.assertRaisesRegex(ValueError,'signature'):
                    mesh.transit_check(altered,node.network)


if __name__=='__main__':unittest.main()
