"""Public commitment counterexamples; no signing, network or backend process."""
import hashlib
import json
from pathlib import Path
import unittest

import pq_permanent_import_reference_candidate as reference


class AppendCommitment(unittest.TestCase):
    def setUp(self):
        self.v = json.loads((Path(__file__).resolve().parents[1]
                             / 'vectors/permanent-import-index-candidate-v1/vectors.json').read_bytes())
        self.scope = bytes.fromhex(self.v['scope'])
        self.root = bytes.fromhex(self.v['root'])

    def prepare(self, c, root=None, scope=None, raw=None):
        return reference.prepare_append(scope or self.scope, root or self.root,
                                        bytes.fromhex(c['query']),
                                        raw if raw is not None else bytes.fromhex(c['proof']))

    def test_shared_vector_append_and_duplicate(self):
        for c in self.v['cases']:
            if c['expected_present']:
                with self.assertRaises(ValueError):
                    self.prepare(c)
            else:
                p = self.prepare(c)
                self.assertEqual(p['new_root'], c['expected_insert_root'])
                self.assertEqual(p['previous_key_count'], c['expected_count'])
                self.assertEqual(p['new_key_count'], c['expected_count'] + 1)

    def test_current_anchor_scope_and_complete_wire_required(self):
        c = self.v['cases'][3]
        p = self.prepare(c)
        for kwargs in ({'root': bytes.fromhex(p['new_root'])},
                       {'scope': bytes([9]) * 64},
                       {'raw': bytes.fromhex(c['proof']) + b'\0'},
                       {'raw': bytes.fromhex(c['proof'])[:-1]},
                       {'raw': b'x' * 32769}):
            with self.assertRaises(ValueError):
                self.prepare(c, **kwargs)

    def test_payload_binds_every_transition_field_and_full_proof(self):
        c = self.v['cases'][3]
        p = self.prepare(c)
        fields = [self.scope, self.root, bytes.fromhex(c['query']), bytes.fromhex(p['new_root']),
                  (5).to_bytes(4, 'big'), (6).to_bytes(4, 'big'),
                  hashlib.sha512(bytes.fromhex(c['proof'])).digest()]
        self.assertEqual(hashlib.sha512(reference.DOMAIN + b''.join(fields)).hexdigest(), p['payload_root'])
        for i in range(len(fields)):
            changed = fields.copy()
            changed[i] = bytes([changed[i][0] ^ 1]) + changed[i][1:]
            self.assertNotEqual(hashlib.sha512(reference.DOMAIN + b''.join(changed)).hexdigest(), p['payload_root'])


if __name__ == '__main__':
    unittest.main()
