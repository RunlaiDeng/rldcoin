"""Diagnostic bounds and unchanged native request sequence; no authority."""
import unittest

import bft_tick_fixture as baseline
from regional_bft_observation import Observation, MAX_EVENTS, MAX_BYTES, MAX_OPERATIONS
import interstellar_transfer as wire


class ObservationTests(unittest.TestCase):
    def test_ring_evicts_explicitly_and_snapshot_never_aliases(self):
        value = Observation()
        for n in range(MAX_EVENTS+7):
            value.event('receive-end', envelope_id='a'*64, succeeded=True, round=n)
        first = value.snapshot()
        self.assertEqual(first['dropped_events'], 7)
        self.assertEqual(first['events'][0]['sequence'], 8)
        self.assertEqual(first['events'][-1]['sequence'], MAX_EVENTS+7)
        first['events'][0]['round'] = -1
        self.assertEqual(value.snapshot()['events'][0]['round'], 7)
        self.assertLessEqual(len(wire.canonical(first)), MAX_BYTES)
        self.assertFalse(first['timing_is_authority'])

    def test_mutable_native_objects_and_unbounded_fields_are_never_retained(self):
        value = Observation()
        for payload in ({'ledger':{'coin':1}}, {'text':'x'*129}, {'values':[1]}, {'text':b'secret'}):
            value.event('invalid', **payload)
        self.assertEqual(value.snapshot()['events'], [])
        self.assertEqual(value.rejected, 4)

    def test_operation_cardinality_and_maximum_event_sizes_stay_bounded(self):
        value = Observation()
        for n in range(MAX_OPERATIONS+1):
            value.operation('operation-'+str(n), value.started, n != 0)
        self.assertEqual(len(value.operations), MAX_OPERATIONS)
        self.assertEqual(value.operations['operation-0']['failures'], 1)
        for _ in range(MAX_EVENTS):
            value.event('large', **{'f'+str(n):'x'*128 for n in range(16)})
        self.assertEqual(len(value.events), 0)
        self.assertLessEqual(len(wire.canonical(value.snapshot())), MAX_BYTES)

    def test_restart_has_no_retained_events_or_native_state(self):
        old = Observation(); old.event('sign-end', succeeded=True)
        new = Observation()
        self.assertEqual(new.snapshot()['sequence'], 0)
        self.assertEqual(new.snapshot()['events'], [])

    def test_observation_preserves_same_round_prepare_commit_and_failure_path(self):
        f = baseline.Fixture(); f.proposal(0); f.votes(0, 'Prepare', 3)
        f.observation = Observation()
        result = f.tick()
        self.assertEqual(f.requests, [dict(kind='Prepare', round=0), dict(kind='Commit', round=0)])
        self.assertEqual(result['native_records'], 2)
        self.assertTrue(f.observation.events[-1]['succeeded'])
        f.broadcast = lambda: (_ for _ in ()).throw(ValueError('fixture publication refusal'))
        with self.assertRaisesRegex(ValueError, 'fixture publication refusal'):
            f.tick()
        self.assertFalse(f.observation.events[-1]['succeeded'])

    def test_two_votes_remain_insufficient_and_keyless_remains_readonly(self):
        for count, readonly in ((2, False), (3, True)):
            f = baseline.Fixture(); f.proposal(0); f.votes(0, 'Prepare', count)
            f.observation = Observation()
            if readonly: f.key_file = None
            f.tick()
            self.assertNotIn(dict(kind='Commit', round=0), f.requests)
            if readonly: self.assertEqual(f.requests, [])

    def test_real_native_changed_envelope_authentication_precedes_success_observation(self):
        import copy
        import test_regional_bft_node as real
        import interstellar_mesh as mesh
        fixture = real.CallerRecoveryTests()
        fixture.setUp()
        try:
            runtime, native, original, updated, certificate = fixture.duplicate_with_new_proof()
            def frame(envelope):
                return wire.make_frame('regional-bft', runtime.region, runtime.region,
                                       mesh.digest(envelope), wire.canonical(envelope))
            runtime.receive(frame(updated))
            self.assertEqual(native.call('status')['tip'], certificate['statement']['block'])
            self.assertTrue(runtime.observation.events[-1]['succeeded'])
            self.assertEqual(runtime.observation.events[-1]['envelope_id'], mesh.digest(updated))
            head = runtime.head_path.read_bytes()
            state = runtime.state_path.read_bytes()
            forged = copy.deepcopy(updated)
            vote = forged['evidence']['snapshots'][0]['snapshot']['bft']['committed']['votes'][0]
            signature = vote['approval']['signature']
            vote['approval']['signature'] = ('0' if signature[0] != '0' else '1') + signature[1:]
            with self.assertRaises(ValueError):
                runtime.receive(frame(forged))
            event = runtime.observation.events[-1]
            self.assertFalse(event['succeeded'])
            self.assertNotIn('envelope_id', event)
            self.assertEqual(runtime.head_path.read_bytes(), head)
            self.assertEqual(runtime.state_path.read_bytes(), state)
        finally:
            fixture.tearDown()


if __name__ == '__main__':
    unittest.main()
