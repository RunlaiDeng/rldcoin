"""Mechanical pinned request/response boundaries; Native crypto is separate."""
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
import regional_bft_pinned_cold as cold
from regional_bft_retention import Messages, pack_state
from verify_regional_bft_stopped_batch import verify_stopped_state_pinned


class PinnedNative:
    currency = '1' * 64
    def __init__(self):
        self.calls, self.inputs = [], []
        self.change = self.history_change = None
    def call(self, action, *args):
        self.calls.append((action, args))
        if action == 'history-check':
            assert args == ('--expected-head', '7' * 64)
            result = dict(history_head='7' * 64, currency=self.currency, region='2' * 64,
                          height=10, tip='4' * 64, logical_native_replay_complete=True,
                          independent_latest_state_anchor_qualified=False, fixture_only=True, live_rld=False)
            return self.history_change(result) if self.history_change else result
        assert action == 'bft-network-check-plan' and args[0] == '--file'
        assert args[2:] == ('--expected-head', '7' * 64)
        path = Path(args[1]); raw = path.read_bytes(); plan = wire.decode_json(raw)
        assert not path.stat().st_mode & 0o077
        results, carried = [], []
        for batch in plan['batches']:
            file = path.parent / (batch['sha256'] + '.json')
            content = file.read_bytes(); entries = wire.decode_json(content)
            assert not file.stat().st_mode & 0o077
            assert len(content) == batch['bytes'] <= 8 * 1024 * 1024
            assert len(entries) == batch['envelopes'] <= 4
            assert hashlib.sha256(content).hexdigest() == batch['sha256']
            carried.append(content)
            results.append(dict(request_sha256=batch['sha256'], results=[
                dict(message_id=mesh.digest(entry['body']), value=None) for entry in entries]))
        self.inputs.append(carried)
        result = dict(format=cold.FORMAT, currency=self.currency, region='2' * 64,
                      history_head='7' * 64, request_sha256=hashlib.sha256(raw).hexdigest(),
                      batches=results, verified=True, ledger_changed=False, signing_authority=False)
        return self.change(result) if self.change else result


class PinnedColdTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.native = PinnedNative()
        self.runtime = SimpleNamespace(root=self.root, native=self.native, region='2' * 64,
                                       state={'messages': Messages()})
    def messages(self, count, size=0):
        table = Messages()
        for n in range(count):
            snapshot = {'mechanical_fixture': 'x' * size}
            envelope = dict(format='RLD-REGIONAL-BFT-NETWORK-V2', currency='1' * 64, region='2' * 64,
                            body={'fixture': n}, evidence={'snapshots': [snapshot, snapshot] if size else []})
            table = table.append(mesh.digest(envelope['body']), envelope, None, n % 2 == 0)
        self.runtime.state['messages'] = table
        return {i: table.payload(i) for i in table}
    def test_exact_complete_order_multiple_references_and_original_bytes(self):
        before = self.messages(10, 20)
        with patch.object(Messages, '__getitem__', side_effect=AssertionError('no mutable envelope cache')):
            answer = cold.check_retained_pinned(self.runtime, '7' * 64)
        self.assertEqual(answer['batches'], 3)
        carried = self.native.inputs[0]
        self.assertEqual([len(wire.decode_json(row)) for row in carried], [4, 4, 2])
        self.assertEqual([wire.canonical(e) for row in carried for e in wire.decode_json(row)], list(before.values()))
        self.assertEqual({i: self.runtime.state['messages'].payload(i) for i in before}, before)
        self.assertEqual(list(self.root.iterdir()), [])
    def test_rotate_before_byte_limit_without_losing_complete_envelopes(self):
        before = self.messages(5, 700)
        with patch.object(cold, 'MAX_INPUT', 4096):
            cold.check_retained_pinned(self.runtime, '7' * 64)
        self.assertTrue(all(len(row) <= 4096 for row in self.native.inputs[0]))
        self.assertEqual([wire.canonical(e) for row in self.native.inputs[0] for e in wire.decode_json(row)], list(before.values()))
    def test_every_response_binding_and_later_bad_value_refuses_without_fallback(self):
        before = self.messages(5)
        def bad_value(result):
            result['batches'][-1]['results'][0]['value'] = 'f' * 64
            return result
        changes = [lambda r: {**r, 'history_head': '8' * 64}, lambda r: {**r, 'currency': 'f' * 64},
                   lambda r: {**r, 'region': 'f' * 64}, lambda r: {**r, 'request_sha256': '0' * 64},
                   lambda r: {**r, 'verified': 1}, lambda r: {**r, 'ledger_changed': True},
                   lambda r: {**r, 'signing_authority': True}, lambda r: {**r, 'batches': r['batches'][::-1]},
                   lambda r: {**r, 'batches': r['batches'][:-1]}, bad_value]
        for change in changes:
            self.native.change = change
            with self.assertRaises(ValueError):
                cold.check_retained_pinned(self.runtime, '7' * 64)
        self.assertTrue(all(action == 'bft-network-check-plan' for action, _ in self.native.calls))
        self.assertEqual({i: self.runtime.state['messages'].payload(i) for i in before}, before)
        self.assertFalse(list(self.root.iterdir()))
    def test_explicit_invalid_head_and_retained_count_refuse_before_native(self):
        self.messages(1)
        for head in (None, True, '0' * 64, 'x' * 64):
            with self.assertRaises(ValueError):
                cold.check_retained_pinned(self.runtime, head)
        self.runtime.state['messages'] = Messages({str(n): b'' for n in range(513)})
        with self.assertRaises(ValueError):
            cold.check_retained_pinned(self.runtime, '7' * 64)
        self.assertEqual(self.native.calls, [])
    def test_fsync_and_total_processed_capacity_fail_before_native(self):
        self.messages(5)
        with patch.object(cold.os, 'fsync', side_effect=OSError('durability refused')):
            with self.assertRaises(OSError):
                cold.check_retained_pinned(self.runtime, '7' * 64)
        with patch.object(cold, 'MAX_ARCHIVE_BYTES', 100):
            with self.assertRaises(ValueError):
                cold.check_retained_pinned(self.runtime, '7' * 64)
        self.assertEqual(self.native.calls, [])
    def test_empty_still_requires_pinned_native_history(self):
        answer = cold.check_retained_pinned(self.runtime, '7' * 64)
        self.assertEqual(answer['messages_authenticated'], 0)
        self.assertEqual(self.native.calls[0][0], 'history-check')
        self.native.history_change = lambda r: {**r, 'history_head': '0' * 64}
        with self.assertRaises(ValueError):
            cold.check_retained_pinned(self.runtime, '7' * 64)
    def test_stopped_pipeline_uses_native_height_tip_no_runtime_and_no_head_adoption(self):
        self.messages(10)
        directory = self.root / 'state'; directory.mkdir(mode=0o700)
        config = dict(state=str(directory), format='RLD-REGIONAL-BFT-NODE-V1', key='3' * 64)
        state = dict(format=config['format'], binding=dict(currency='1' * 64, region='2' * 64, key='3' * 64),
                     messages=self.runtime.state['messages'], height=10, tip='4' * 64, snapshot_cache=[], cursor=0)
        path = directory / 'state.json'; mesh.atomic(path, pack_state(state)); before = path.read_bytes()
        with patch('regional_bft_node.Runtime.__init__', side_effect=AssertionError('no Runtime startup')):
            result = verify_stopped_state_pinned(self.native, config, self.root, '7' * 64)
        self.assertEqual([a for a, _ in self.native.calls], ['history-check', 'bft-network-check-plan'])
        self.assertFalse(result['implicit_head_adoption'])
        self.assertEqual(result['messages_authenticated'], 10)
        self.assertEqual(path.read_bytes(), before)
        state['height'] = 11; mesh.atomic(path, pack_state(state)); self.native.calls.clear()
        with self.assertRaises(ValueError):
            verify_stopped_state_pinned(self.native, config, self.root, '7' * 64)
        self.assertEqual([a for a, _ in self.native.calls], ['history-check'])
    def test_native_whole_failure_is_not_retried_or_reported_as_partial_success(self):
        self.messages(10)
        self.native.change = lambda r: (_ for _ in ()).throw(ValueError('later Native certificate refused'))
        with self.assertRaisesRegex(ValueError, 'certificate refused'):
            cold.check_retained_pinned(self.runtime, '7' * 64)
        self.assertEqual(len(self.native.calls), 1)
        self.assertFalse(list(self.root.iterdir()))


if __name__ == '__main__':
    unittest.main()
