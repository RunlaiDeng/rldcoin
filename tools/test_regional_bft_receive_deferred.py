"""Typed Native receive refusal boundaries; no Native/Runtime/socket starts."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from regional_contact_node import Service, NativeRefusal

BUSY = 'regional candidate rejected: lock acquisition failed because the operation would block'


class ReceiveDeferredTests(unittest.TestCase):
    def service(self, error=None):
        service = Service.__new__(Service)
        service.bft = SimpleNamespace(receive_many=Mock(side_effect=error))
        service.bft_seen = {'previous'}
        service.bft_individual_retry = False
        service.contact_trace = SimpleNamespace(native_received=Mock())
        return service

    def receive(self, service, count=2):
        rows = [(str(n), b'exact-complete-' + bytes([n])) for n in range(count)]
        before = copy.deepcopy(rows)
        errors, rejected, deferred = [], [], []
        service.receive_bft_batch(rows, errors, rejected, deferred)
        self.assertEqual(rows, before)
        service.bft.receive_many.assert_called_with([raw for _, raw in rows])
        return errors, rejected, deferred

    def test_exact_typed_lock_defers_without_seen_or_trace_credit(self):
        for action in ('bft-network-inspect-batch', 'bft-network-check', 'bft-sync', 'bft-context'):
            with self.subTest(action=action):
                service = self.service(NativeRefusal(action, 1, BUSY))
                errors, rejected, deferred = self.receive(service)
                self.assertEqual(errors, ['native rejected: ' + BUSY])
                self.assertEqual(rejected, [])
                self.assertEqual(len(deferred), 2)
                self.assertTrue(all(v['command'] == action and v['exit_code'] == 1
                                    and not v['ledger_acceptance_known']
                                    and not v['signing_authority'] for v in deferred))
                self.assertEqual(service.bft_seen, {'previous'})
                service.contact_trace.native_received.assert_not_called()
                self.assertTrue(service.bft_individual_retry)

    def test_next_success_checks_complete_original_bytes_before_seen_credit(self):
        service = self.service(NativeRefusal('bft-network-inspect-batch', 1, BUSY))
        self.receive(service)
        service.bft.receive_many.side_effect = None
        errors, rejected, deferred = self.receive(service)
        self.assertEqual((errors, rejected, deferred), ([], [], []))
        self.assertEqual(service.bft_seen, {'previous', '0', '1'})
        self.assertEqual(service.bft.receive_many.call_count, 2)
        self.assertEqual(service.contact_trace.native_received.call_count, 2)

    def test_altered_proof_after_deferral_still_rejects(self):
        service = self.service(NativeRefusal('bft-network-inspect-batch', 1, BUSY))
        self.receive(service)
        service.bft.receive_many.side_effect = NativeRefusal('bft-network-inspect-batch', 1,
                                                           'regional candidate rejected: invalid later proof')
        errors, rejected, deferred = self.receive(service)
        self.assertEqual(len(errors), 1)
        self.assertEqual(len(rejected), 2)
        self.assertEqual(deferred, [])
        self.assertEqual(service.bft_seen, {'previous'})
        service.contact_trace.native_received.assert_not_called()

    def test_unbound_wrong_action_exit_and_complete_later_diagnostic_do_not_defer(self):
        for error in (ValueError('native rejected: ' + BUSY),
                      NativeRefusal('bft-sign', 1, BUSY),
                      NativeRefusal('bft-network-inspect-batch', 2, BUSY),
                      NativeRefusal('bft-network-inspect-batch', True, BUSY),
                      NativeRefusal('bft-network-inspect-batch', 1, BUSY + ' ' * 2200 + 'bad proof'),
                      NativeRefusal('bft-network-inspect-batch', 1, 'Permission denied'),
                      OSError('persistence failure')):
            with self.subTest(error=str(error)):
                service = self.service(error)
                _, rejected, deferred = self.receive(service)
                self.assertEqual(len(rejected), 2)
                self.assertEqual(deferred, [])
                self.assertEqual(service.bft_seen, {'previous'})

    def test_existing_seen_hint_cannot_skip_a_later_complete_proof(self):
        service = self.service(NativeRefusal('bft-network-inspect-batch', 1, 'invalid later proof'))
        service.bft_seen.add('0')
        _, rejected, deferred = self.receive(service, 1)
        self.assertEqual(len(rejected), 1)
        self.assertEqual(deferred, [])
        self.assertFalse(service.bft_individual_retry)


if __name__ == '__main__':
    unittest.main()
