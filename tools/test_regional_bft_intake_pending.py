"""Selected-input retry/signing boundaries, without claiming Native authority."""
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import interstellar_mesh as mesh
from regional_bft_intake_pending import IntakePending, LIMIT, Pending
from regional_bft_node import Runtime
from regional_contact_node import NativeRefusal, Service

BUSY = 'regional candidate rejected: lock acquisition failed because the operation would block'
IDS = [f'{n:064x}' for n in range(1, 7)]


class PendingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name).resolve() / 'pending.json'
        self.binding = dict(runtime='fixture', ledger=str(self.path.parent))
        self.pending = Pending(self.path, self.binding, fresh=True)

    def test_restart_retains_exact_selected_ids_until_complete_retry(self):
        self.pending.begin(IDS[:2])
        restored = Pending(self.path, self.binding, fresh=False)
        self.assertEqual(restored.packets, frozenset(IDS[:2]))
        with self.assertRaises(IntakePending): restored.before_sign()
        restored.finish(IDS[:1])
        with self.assertRaises(IntakePending): restored.before_sign()
        restored.finish(IDS[1:2])
        restored.before_sign()
        self.assertEqual(Pending(self.path, self.binding, fresh=False).packets, frozenset())

    def test_old_progress_missing_or_changed_binding_refuses_without_rewrite(self):
        raw = self.path.read_bytes()
        with self.assertRaises(ValueError): Pending(self.path, dict(runtime='other'), fresh=False)
        self.assertEqual(self.path.read_bytes(), raw)
        self.path.unlink()
        with self.assertRaises(ValueError): Pending(self.path, self.binding, fresh=False)
        self.assertFalse(self.path.exists())

    def test_corrupt_order_capacity_type_and_id_refuse(self):
        original = json.loads(self.path.read_bytes())
        for packets in (IDS[:LIMIT+1], [IDS[1], IDS[0]], [IDS[0], IDS[0]], ['bad'], [True]):
            with self.subTest(packets=packets):
                value = dict(original, packets=packets)
                mesh.atomic(self.path, value)
                raw = self.path.read_bytes()
                with self.assertRaises(ValueError): Pending(self.path, self.binding, fresh=False)
                self.assertEqual(self.path.read_bytes(), raw)

    def test_failed_write_and_capacity_freeze_signing_without_clearing_previous_ids(self):
        self.pending.begin(IDS[:1])
        raw = self.path.read_bytes()
        with patch.object(mesh, 'atomic', side_effect=OSError('durability failure')):
            with self.assertRaises(OSError): self.pending.finish(IDS[:1])
        self.assertEqual(self.path.read_bytes(), raw)
        self.assertEqual(self.pending.packets, frozenset(IDS[:1]))
        with self.assertRaises(IntakePending): self.pending.before_sign()
        with self.assertRaises(IntakePending): self.pending.finish(IDS[:1])
        restored = Pending(self.path, self.binding, fresh=False)
        with self.assertRaises(ValueError): restored.begin(IDS[1:LIMIT+1])
        self.assertEqual(self.path.read_bytes(), raw)
        with self.assertRaises(IntakePending): restored.before_sign()

    def test_gate_precedes_native_request_head_change_and_timeout_trace(self):
        self.pending.begin(IDS[:1])
        runtime = SimpleNamespace(before_sign=self.pending.before_sign, _sign=Mock(),
                                  observation=SimpleNamespace(event=Mock()),
                                  contact_trace=SimpleNamespace(event=Mock()),
                                  head=dict(head='exact', pending=None, outbox=None), entered_at=123)
        with self.assertRaises(IntakePending): Runtime.sign(runtime, {'Timeout': {'round': 0}})
        runtime._sign.assert_not_called()
        runtime.observation.event.assert_not_called()
        runtime.contact_trace.event.assert_not_called()
        self.assertEqual(runtime.head, dict(head='exact', pending=None, outbox=None))
        self.assertEqual(runtime.entered_at, 123)

    def service(self, error):
        service = Service.__new__(Service)
        service.bft = SimpleNamespace(receive_many=Mock(side_effect=error), state={'messages': {}})
        service.bft_seen = set()
        service.bft_individual_retry = False
        service.contact_trace = None
        service.bft_intake_pending = self.pending
        service.receive_after = {'novel': None, 'background': None}
        return service

    def receive(self, service):
        rows = [(IDS[0], b'exact-complete-envelope')]
        errors, rejected, deferred = [], [], []
        service.receive_bft_batch(rows, errors, rejected, deferred)
        service.bft.receive_many.assert_called_with([rows[0][1]])
        return errors, rejected, deferred

    def test_lock_deferral_persists_before_native_and_success_clears_before_seen(self):
        service = self.service(NativeRefusal('history-head', 1, BUSY))
        def locked(_):
            self.assertEqual(Pending(self.path, self.binding, fresh=False).packets, frozenset(IDS[:1]))
            raise NativeRefusal('history-head', 1, BUSY)
        service.bft.receive_many.side_effect = locked
        errors, rejected, deferred = self.receive(service)
        self.assertEqual(len(errors), 1)
        self.assertEqual(rejected, [])
        self.assertEqual(len(deferred), 1)
        self.assertEqual(service.bft_seen, set())
        with self.assertRaises(IntakePending): self.pending.before_sign()
        service.bft.receive_many.side_effect = None
        self.assertEqual(self.receive(service), ([], [], []))
        self.pending.before_sign()
        self.assertEqual(service.bft_seen, set(IDS[:1]))

    def test_unknown_os_timeout_retains_fence_complete_refusal_closes_without_seen(self):
        for error in (OSError('unknown persistence'), subprocess.TimeoutExpired('Native', 1),
                      NativeRefusal('history-head', 1, BUSY)):
            with self.subTest(error=type(error).__name__):
                service = self.service(error)
                self.receive(service)
                with self.assertRaises(IntakePending): self.pending.before_sign()
                service.bft.receive_many.side_effect = NativeRefusal('bft-origin-network-receive-batch', 1,
                                                                    'invalid complete signature')
                _, rejected, deferred = self.receive(service)
                self.assertEqual(len(rejected), 1)
                self.assertEqual(deferred, [])
                self.assertEqual(service.bft_seen, set())
                self.pending.before_sign()

    def test_post_acceptance_fence_write_failure_grants_no_seen_or_signing(self):
        service = self.service(None)
        original = mesh.atomic
        writes = 0
        def fail_clear(*args):
            nonlocal writes
            writes += 1
            if writes == 2: raise OSError('unknown directory fsync')
            return original(*args)
        with patch.object(mesh, 'atomic', side_effect=fail_clear): self.receive(service)
        self.assertEqual(service.bft_seen, set())
        with self.assertRaises(IntakePending): self.pending.before_sign()
        self.assertEqual(Pending(self.path, self.binding, fresh=False).packets, frozenset(IDS[:1]))

    def test_pending_selection_preserves_four_attempt_budget_and_missing_custody_block(self):
        service = self.service(None)
        self.pending.begin(IDS[:4])
        summaries = {i: dict(destination='node', kind='regional-bft', export_id=i) for i in IDS}
        receipts = {i: {} for i in IDS}
        quota = {'attempted': set(IDS[:3])}
        self.assertEqual(service.receive_candidates(summaries, receipts, 'node', quota), IDS[3:4])
        self.assertEqual(len(quota['attempted']), LIMIT)
        self.assertEqual(service.receive_candidates(summaries, receipts, 'node', quota), [])
        self.assertEqual(service.receive_candidates(summaries, {IDS[4]: {}}, 'node'), [])
        with self.assertRaises(IntakePending): self.pending.before_sign()
        self.assertEqual(service.bft_seen, set())

    def test_metadata_bytes_refuse_before_publication_or_native_authority(self):
        raw = self.path.read_bytes()
        self.pending.binding = {'oversized': 'x' * 8192}
        with self.assertRaises(ValueError): self.pending.begin(IDS[:1])
        self.assertEqual(self.path.read_bytes(), raw)
        with self.assertRaises(IntakePending): self.pending.before_sign()

    def test_service_tick_reports_unknown_progress_when_gate_blocks(self):
        from test_regional_bft_receive_deferred import ContactApplyDeferredTests
        case = ContactApplyDeferredTests()
        service, _, raw = case.service(None)
        service.native.apply.return_value = {'evidence_verified': True, 'import_accepted': False}
        service.bft = SimpleNamespace(tick=Mock(side_effect=IntakePending('intake pending')),
                                      state={'messages': {}},
                                      observation=SimpleNamespace(event=Mock(), snapshot=lambda: {}))
        report = case.tick(service, raw)
        self.assertEqual(report['errors'], [])
        self.assertFalse(report['consensus']['progress_observation_available'])
        self.assertFalse(report['consensus']['autonomous_signing_enabled'])
        self.assertNotIn('height', report['consensus'])
        self.assertNotIn('round', report['consensus'])
        service.bft.observation.event.assert_any_call('native-intake-signing-deferred')


if __name__ == '__main__': unittest.main()
