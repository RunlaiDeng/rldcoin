"""Exact sign custody order and bounded cost attribution; zero Native startup."""
import copy
from pathlib import Path
import unittest
from unittest.mock import patch

from regional_bft_node import Runtime
from regional_bft_observation import Observation, MAX_EVENTS, MAX_OPERATIONS, MAX_BYTES
import interstellar_transfer as wire

STAGES = ('status', 'pending', 'native', 'response', 'outbox')
DURATIONS = (1.0, .25, 2.0, .5, 4.0)
REQUEST = {'Timeout': {'fixture': 'unchanged-request'}}


class Fixture:
    _sign = Runtime._sign
    _sign_stage = Runtime._sign_stage

    def __init__(self, failure=None):
        self.failure = failure
        self.order = []
        self.clock = 0.0
        self.entered_at = -1.0
        self.key_file = Path('/synthetic/key-file-never-opened')
        self.signer = Path('/synthetic/signer-never-opened')
        self.head = dict(head='a' * 64, pending=None, outbox=None)
        self.result = dict(head='b' * 64, message={'Timeout': {'fixture': 'native-response'}})
        self.native_requests = []

    def step(self, name):
        self.order.append(name)
        self.clock += DURATIONS[STAGES.index(name)]
        if self.failure == name:
            raise ValueError('injected ' + name)

    def signer_status(self):
        self.step('status')

    def save_head(self, value):
        self.step('pending' if value['pending'] is not None else 'response')
        self.head = copy.deepcopy(value)

    def with_json(self, action, request, *args):
        assert action == 'bft-sign'
        assert args == ('--signer-dir', self.signer, '--expected-head', 'a'*64, '--key-file', self.key_file)
        self.native_requests.append(copy.deepcopy(request))
        self.step('native')
        return copy.deepcopy(self.result)

    def flush_outbox(self):
        self.step('outbox')
        assert self.head['outbox'] == self.result['message']
        self.head['outbox'] = None

    def run(self, observed=True, saturated=False):
        with patch('regional_bft_node.private', return_value=self.key_file), \
                patch('regional_bft_node.time.monotonic', side_effect=lambda: self.clock):
            if observed:
                self.observation = Observation()
                if saturated:
                    for n in range(MAX_OPERATIONS):
                        self.observation.operation('existing-' + str(n), self.clock, True)
                    for _ in range(MAX_EVENTS):
                        self.observation.event('existing')
            return self._sign(copy.deepcopy(REQUEST))


class SignObservationTests(unittest.TestCase):
    def test_complete_path_costs_do_not_change_request_or_custody_sequence(self):
        f = Fixture(); f.run()
        self.assertEqual(f.order, list(STAGES))
        self.assertEqual(f.native_requests, [REQUEST])
        self.assertEqual(f.head, dict(head='b'*64, pending=None, outbox=None))
        self.assertEqual(f.entered_at, sum(DURATIONS))
        snap = f.observation.snapshot()
        self.assertEqual([v['stage'] for v in snap['events']], list(STAGES))
        for name, duration in zip(STAGES, DURATIONS):
            self.assertEqual(snap['operations']['sign-' + name],
                             dict(calls=1, failures=0, total_seconds=duration, max_seconds=duration))
        self.assertFalse(snap['timing_is_authority'])

    def test_failure_before_native_never_first_signs_and_only_visited_stages_record(self):
        for failed in ('status', 'pending'):
            with self.subTest(failed=failed):
                f = Fixture(failed)
                with self.assertRaisesRegex(ValueError, 'injected ' + failed): f.run()
                self.assertEqual(f.native_requests, [])
                self.assertEqual(f.head, dict(head='a'*64, pending=None, outbox=None))
                self.assertEqual(f.entered_at, -1)
                events = f.observation.snapshot()['events']
                self.assertEqual([v['stage'] for v in events], list(STAGES[:STAGES.index(failed)+1]))
                self.assertFalse(events[-1]['succeeded'])

    def test_post_native_failures_retain_original_pending_or_exact_response(self):
        for failed in ('native', 'response', 'outbox'):
            with self.subTest(failed=failed):
                f = Fixture(failed)
                with self.assertRaisesRegex(ValueError, 'injected ' + failed): f.run()
                self.assertEqual(f.native_requests, [REQUEST])
                self.assertEqual(f.head, dict(head='b'*64, pending=None, outbox=f.result['message'])
                                 if failed == 'outbox' else dict(head='a'*64, pending=REQUEST, outbox=None))
                self.assertEqual(f.entered_at, -1)
                self.assertFalse(f.observation.snapshot()['events'][-1]['succeeded'])
                self.assertEqual(f.observation.operations['sign-' + failed]['failures'], 1)

    def test_absent_or_saturated_diagnostics_never_change_request_or_head_order(self):
        for observed, saturated in ((False, False), (True, True)):
            with self.subTest(observed=observed):
                f = Fixture(); f.run(observed, saturated)
                self.assertEqual(f.order, list(STAGES)); self.assertEqual(f.native_requests, [REQUEST])
                self.assertEqual(f.head, dict(head='b'*64, pending=None, outbox=None))
                self.assertEqual(f.entered_at, sum(DURATIONS))
                if observed:
                    snap = f.observation.snapshot()
                    self.assertEqual(len(snap['operations']), MAX_OPERATIONS)
                    self.assertEqual(len(snap['events']), MAX_EVENTS)
                    self.assertEqual(snap['dropped_events'], len(STAGES))
                    self.assertEqual(snap['rejected_events'], len(STAGES))
                    self.assertLessEqual(len(wire.canonical(snap)), MAX_BYTES)

    def test_observations_contain_no_request_head_response_or_key_path(self):
        f = Fixture(); f.run(); snap = f.observation.snapshot()
        raw = wire.canonical(snap)
        for secret in (b'unchanged-request', b'native-response', b'a'*64, b'b'*64,
                       b'key-file-never-opened', b'signer-never-opened'):
            self.assertNotIn(secret, raw)
        snap['events'][0]['stage'] = 'altered'
        self.assertEqual(f.observation.snapshot()['events'][0]['stage'], 'status')


if __name__ == '__main__': unittest.main()
