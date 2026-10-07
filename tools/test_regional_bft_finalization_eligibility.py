"""Actual runtime orchestration tests; fake Native refuses/records calls only.

These tests establish eligibility and refusal propagation, never Native quorum,
signing, cold-state or monetary authority.
"""
from pathlib import Path
from types import SimpleNamespace
import unittest

from regional_bft_node import Runtime, FORMAT


class RecordingRuntime(Runtime):
    def __init__(self, prepare_count=3, commit_count=2, keyless=False, reject=None,
                 active_prepared=True, round_number=0):
        self.context = {'parent_height': 13}
        self.value = 'candidate'
        self.proposal = {'round': round_number}
        self.proposal_round = round_number
        self.prepare_count, self.commit_count = prepare_count, commit_count
        self.reject = reject
        self.events = []
        self.failed = False
        self.head = {'pending': None, 'head': 'caller'}
        self.native = SimpleNamespace(ledger=Path(__file__).parent / 'nonexistent-unit-spool')
        self.format, self.joint = FORMAT, None
        self.state = {'height': 13}
        self.slot, self.entered_at = None, None
        self.stop_height = 15
        self.key_file = None if keyless else Path(__file__)
        self.active = {'context': self.context, 'round': 0,
                       'prepared': self.value if active_prepared else None,
                       'committed': None, 'proposed': True}
        self.round_timeout = 60
        self.block_interval = 1
        self.peers = {'a': {}, 'b': {}, 'c': {}, 'd': {}}
        self.key = 'a'

    def flush_outbox(self):
        pass

    def loop_observation(self):
        return self.context, {'state': self.active}

    def signed(self, context, round_number, kind, phase=None, value=None):
        if round_number != self.proposal_round:
            return []
        if kind == 'Proposal':
            return [(self.proposal, self.value)]
        if kind == 'Vote':
            count = self.prepare_count if phase == 'Prepare' else self.commit_count
            return [({'approval': {'key': k}, 'phase': phase}, self.value)
                    for k in 'abcd'[:count]]
        return []

    def with_json(self, command, body, *args):
        phase = body[0]['phase'] if command == 'bft-quorum' else None
        self.events.append((command, phase))
        if self.reject == (command, phase):
            raise ValueError('Native refused exact input')
        if command == 'bft-quorum':
            return {'phase': phase}
        if command == 'bft-certify':
            assert body['prepared'] == {'phase': 'Prepare'}
            assert body['committed'] == {'phase': 'Commit'}
            return {'certificate': True}
        if command == 'finalize':
            self.state['height'] = 14
            return None
        raise AssertionError(command)

    def _try_prepare(self, proposal):
        self.events.append(('native-prepare', None))
        return True

    def signer_status(self):
        return {'state': self.active}

    def sign(self, request):
        self.events.append(('native-sign', next(iter(request))))
        if self.reject == ('native-sign', 'Commit'):
            raise ValueError('Native durable lock refused')

    def envelope(self, body):
        return body

    def retain(self, body, **kwargs):
        self.events.append(('retain', None))

    def observe(self):
        return self.context

    def broadcast(self):
        self.events.append(('broadcast', None))

    def report(self, *args, **kwargs):
        return self.events


class FinalizationEligibilityTests(unittest.TestCase):
    def test_incomplete_commit_aggregates_prepare_only_for_current_signing(self):
        runtime = RecordingRuntime()
        runtime._tick()
        self.assertEqual(runtime.events.count(('bft-quorum', 'Prepare')), 1)
        self.assertIn(('native-sign', 'Commit'), runtime.events)
        self.assertNotIn(('finalize', None), runtime.events)

    def test_incomplete_commit_keyless_has_no_native_aggregation_or_signing(self):
        runtime = RecordingRuntime(keyless=True)
        runtime._tick()
        self.assertEqual(runtime.events, [('broadcast', None)])

    def test_complete_delayed_round_keyless_requires_both_native_aggregates(self):
        runtime = RecordingRuntime(commit_count=3, keyless=True, round_number=7)
        runtime._tick()
        self.assertEqual(runtime.events[:4], [('bft-quorum', 'Commit'),
                         ('bft-quorum', 'Prepare'), ('bft-certify', None), ('finalize', None)])
        self.assertNotIn(('native-sign', 'Commit'), runtime.events)

    def test_incomplete_prepare_cannot_finalize_even_with_complete_commit(self):
        runtime = RecordingRuntime(prepare_count=2, commit_count=3, keyless=True)
        runtime._tick()
        self.assertEqual(runtime.events, [('bft-quorum', 'Commit'), ('broadcast', None)])

    def test_every_native_refusal_prevents_finalize_or_sign(self):
        for refusal in [('bft-quorum', 'Commit'), ('bft-quorum', 'Prepare'),
                        ('bft-certify', None)]:
            with self.subTest(refusal=refusal):
                runtime = RecordingRuntime(commit_count=3, reject=refusal)
                with self.assertRaisesRegex(ValueError, 'Native refused'):
                    runtime._tick()
                self.assertNotIn(('finalize', None), runtime.events)
                self.assertNotIn(('native-sign', 'Commit'), runtime.events)

    def test_current_commit_signing_keeps_native_lock_refusal(self):
        runtime = RecordingRuntime(reject=('native-sign', 'Commit'))
        with self.assertRaisesRegex(ValueError, 'durable lock refused'):
            runtime._tick()
        self.assertNotIn(('finalize', None), runtime.events)

    def test_no_prepare_quorum_still_uses_native_prepare(self):
        runtime = RecordingRuntime(prepare_count=2, active_prepared=False)
        runtime._tick()
        self.assertIn(('native-prepare', None), runtime.events)
        self.assertNotIn(('native-sign', 'Commit'), runtime.events)
        self.assertNotIn(('finalize', None), runtime.events)


if __name__ == '__main__':
    unittest.main()
