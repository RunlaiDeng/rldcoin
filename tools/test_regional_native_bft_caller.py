"""Fresh actual BFT caller custody with independent pre-migration Python comparison.

Public fixture keys only; no mainnet, independent freshness or cross-device claim.
"""
import copy
import hashlib
from types import MethodType
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
import regional_bft_caller_reference as reference
from test_regional_bft_node import CallerRecoveryTests


class NativeCallerTests(unittest.TestCase):
    setUp = CallerRecoveryTests.setUp
    tearDown = CallerRecoveryTests.tearDown
    open = CallerRecoveryTests.open
    timeout = CallerRecoveryTests.timeout

    def reference(self, runtime):
        old = copy.copy(runtime)
        old.head = copy.deepcopy(runtime.head)
        old.head_path = self.c.root/'reference-caller.json'
        mesh.atomic(old.head_path, old.head)
        old.save_head = MethodType(reference.save_head, old)
        return old

    def test_unsigned_pending_recovery_matches_python_without_first_sign(self):
        runtime = self.open()
        runtime.save_head(dict(runtime.head, pending=self.timeout()))
        old = self.reference(runtime)
        reference.reconcile(old)
        runtime.reconcile()
        self.assertEqual(runtime.head, old.head)
        self.assertEqual(runtime.head_path.read_bytes(), old.head_path.read_bytes())
        self.assertEqual(runtime.signer_status()['records'], 0)

    def test_original_signed_response_matches_python_and_cold_keyless_outbox(self):
        runtime = self.open(); request = self.timeout()
        runtime.save_head(dict(runtime.head, pending=request))
        signed = runtime.with_json('bft-sign', request, '--signer-dir', runtime.signer,
                                  '--expected-head', runtime.head['head'], '--key-file', runtime.key_file)
        runtime.key_file.unlink()
        old = self.reference(runtime)
        reference.reconcile(old)
        runtime.reconcile()
        self.assertEqual(runtime.head, old.head)
        self.assertEqual(runtime.head_path.read_bytes(), old.head_path.read_bytes())
        self.assertEqual(runtime.head['outbox'], signed['message'])
        runtime.close(); self.runtime = None
        cold = self.open()
        self.assertIsNone(cold.head['outbox'])
        self.assertIsNone(cold.head['pending'])
        self.assertEqual(cold.signer_status()['records'], 1)
        self.assertTrue(any(record['envelope']['body'] == {'Signed': signed['message']}
                            for record in cold.state['messages'].values()))

    def test_stale_or_forged_native_transitions_preserve_both_custodies(self):
        runtime = self.open(); old = copy.deepcopy(runtime.head)
        before = (runtime.head_path.read_bytes(), (runtime.signer/'bft.json').read_bytes())
        value = dict(previous_sha256=hashlib.sha256(wire.canonical(old)).hexdigest(),
                     proposed=dict(old, pending=self.timeout()))
        stale = dict(value, previous_sha256='0'*64)
        forged = dict(value, proposed=dict(old, head='7'*64))
        extra = dict(value, proposed=dict(value['proposed'], ignored='must-refuse'))
        for case in (stale, forged, extra):
            with self.subTest(case=list(case)), self.assertRaises(ValueError):
                runtime.with_json('bft-client-store', case['proposed'], *runtime.caller_args(),
                                  '--expected-state-sha256', case['previous_sha256'])
            self.assertEqual((runtime.head_path.read_bytes(), (runtime.signer/'bft.json').read_bytes()), before)
        runtime.save_head(value['proposed'])
        current = copy.deepcopy(runtime.head)
        with self.assertRaises(ValueError):
            runtime.with_json('bft-client-store', dict(current, outbox={'Timeout':{}}),
                              *runtime.caller_args(), '--expected-state-sha256',
                              hashlib.sha256(wire.canonical(current)).hexdigest())
        self.assertEqual(runtime.head, current)
        self.assertEqual((runtime.signer/'bft.json').read_bytes(), before[1])

    def publication_loss(self, lost_store):
        runtime = self.open(); native = runtime.native.call; calls = 0
        def call(action, *args, **kwargs):
            nonlocal calls
            result = native(action, *args, **kwargs)
            if action == 'bft-client-store':
                calls += 1
                if calls == lost_store: raise OSError('original native caller response lost after durable publication')
            return result
        with patch.object(runtime.native, 'call', side_effect=call), self.assertRaises(OSError):
            runtime.sign(self.timeout())
        self.assertTrue(runtime.failed)
        runtime.close(); self.runtime = None
        cold = self.open()
        self.assertIsNone(cold.head['pending']); self.assertIsNone(cold.head['outbox'])
        self.assertEqual(cold.signer_status()['records'], 0 if lost_store == 1 else 1)

    def test_pending_publication_response_loss_never_releases_a_new_signature(self):
        self.publication_loss(1)

    def test_signed_response_publication_loss_replays_exact_outbox_on_cold_start(self):
        self.publication_loss(2)

if __name__ == '__main__':
    unittest.main()
