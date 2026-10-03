"""Counterexamples for physical latency and finite queue planning."""
import copy
import unittest
import interstellar_route_budget as b


def route(**overrides):
    value = dict(payload_bytes=1024, evidence_frames=1, additional_frames_per_day=0,
                 blackout_seconds=0, backlog_frames=0, backlog_bytes=0,
                 usable_bytes_per_second=100000, contact_window_seconds=3600, one_way_seconds=0)
    value.update(overrides)
    return value


def scenario(**overrides):
    value = dict(name='test', forward=route(), **{'return':route()}, maturity_blocks=6, assumed_block_seconds=600)
    value.update(overrides)
    return value


class RouteBudgetTests(unittest.TestCase):
    def test_real_serialized_frame_overhead_is_counted(self):
        value=b.direction(route(payload_bytes=3*1024*1024))
        self.assertGreater(value['frame_bytes'], 4*1024*1024)

    def test_exact_frame_capacity_and_one_over(self):
        self.assertEqual(b.direction(route(evidence_frames=4096))['blocking_constraints'], [])
        self.assertIn('QUEUE_FRAME_LIMIT', b.direction(route(evidence_frames=4097))['blocking_constraints'])

    def test_bytes_bind_before_frame_count(self):
        v=b.direction(route(payload_bytes=3*1024*1024,evidence_frames=64,contact_window_seconds=100000))
        self.assertIn('QUEUE_BYTE_LIMIT',v['blocking_constraints'])
        self.assertNotIn('QUEUE_FRAME_LIMIT',v['blocking_constraints'])

    def test_blackout_arrivals_and_no_silent_eviction(self):
        v=b.direction(route(blackout_seconds=21*b.DAY,additional_frames_per_day=1440))
        self.assertEqual(v['new_frames_during_blackout'],30240)
        self.assertIsNone(v['arrival_after_phase_start_seconds'])
        self.assertEqual(v['queue_copies_after_send'],30241)

    def test_partial_day_is_conservatively_rounded_up(self):
        self.assertEqual(b.direction(route(blackout_seconds=1,additional_frames_per_day=1))['new_frames_during_blackout'],1)

    def test_contact_must_fit_entire_fifo_batch(self):
        v=route(usable_bytes_per_second=1)
        size=b.direction(v)['frame_bytes']
        self.assertEqual(b.direction({**v,'contact_window_seconds':size})['blocking_constraints'],[])
        self.assertIn('CONTACT_WINDOW_TOO_SHORT',b.direction({**v,'contact_window_seconds':size-1})['blocking_constraints'])

    def test_both_light_legs_and_maturity_are_counted(self):
        leg=route(one_way_seconds=17*b.YEAR//4)
        result=b.evaluate(scenario(forward=leg,**{'return':leg}))
        self.assertGreater(result['conditional_round_trip_years'],8.5)
        self.assertFalse(result['route_qualified'])

    def test_failed_return_cannot_report_completed_round_trip(self):
        result=b.evaluate(scenario(**{'return':route(contact_window_seconds=0)}))
        self.assertIsNone(result['conditional_round_trip_seconds'])

    def test_rejects_malformed_or_unbounded_inputs(self):
        for changes in ({'payload_bytes':True},{'usable_bytes_per_second':0},{'blackout_seconds':-1},
                        {'one_way_seconds':float('inf')},{'payload_bytes':b.courier.MAX_PAYLOAD+1},
                        {'backlog_frames':1},{'backlog_bytes':50},{'payload_bytes':10**31}):
            with self.assertRaises(ValueError): b.direction(route(**changes))
        with self.assertRaises(ValueError): b.evaluate(scenario(maturity_blocks=5))
        with self.assertRaises(ValueError): b.evaluate({**scenario(),'optimistic_refund':True})

    def test_does_not_modify_input(self):
        value=scenario(); original=copy.deepcopy(value)
        b.evaluate(value)
        self.assertEqual(value,original)

if __name__ == '__main__': unittest.main()
