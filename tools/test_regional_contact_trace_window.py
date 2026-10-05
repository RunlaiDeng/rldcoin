"""Exact producer, missing/gapped intervals and bounds decide trace usability."""
import unittest
from types import SimpleNamespace
from pathlib import Path
import interstellar_transfer as wire
from unittest.mock import patch

from regional_contact_trace import ContactTrace, MAX_EVENTS
from regional_contact_trace_window import TraceWindow


class WindowTests(unittest.TestCase):
    def setUp(self):
        self.network = 'a' * 64
        self.slots = {i: (100 + i, format(i + 1, '064x')) for i in range(4)}
        self.window = TraceWindow(self.network, self.slots, deadline=180)
        self.traces = {}
        for i, (_, node) in self.slots.items():
            trace = ContactTrace(); trace.bind(self.network, node)
            self.traces[i] = trace

    def status(self, i):
        return dict(process_id=self.slots[i][0], contact_trace=self.traces[i].snapshot(),
                    native_observation={'private_key': 'never-retain', 'height': 999})

    def sample(self, i, now=1):
        return self.window.sample(i, self.status(i), now=now)

    def test_all_exact_delta_rows_once_and_no_native_content_retained(self):
        for i in range(4):
            self.traces[i].event('contact_start')
            self.assertEqual(len(self.sample(i)['events']), 1)
            self.assertEqual(self.sample(i)['events'], [])
        view = self.window.snapshot()
        self.assertEqual(len(view['events']), 4)
        self.assertTrue(view['all_four_streams_observed'])
        self.assertNotIn('never-retain', str(view))
        self.assertFalse(view['authority'])
        view['events'].clear()
        self.assertEqual(len(self.window.snapshot()['events']), 4)

    def test_missing_observation_or_disabled_trace_stays_unknown(self):
        for status in (None, {'process_id': 100}):
            result = self.window.sample(0, status, now=1)
            self.assertFalse(result['available'])
            self.assertIsNone(result['events'])
        view = self.window.snapshot()
        self.assertEqual(view['unknown'][0], 2)
        self.assertFalse(view['all_four_streams_observed'])
        self.assertEqual(view['samples'][0], 0)

    def test_later_wrong_producer_refuses_and_window_cannot_resume(self):
        self.sample(0)
        bad = self.status(0); bad['process_id'] = 101
        with self.assertRaisesRegex(ValueError, 'PID differs'):
            self.window.sample(0, bad, now=2)
        with self.assertRaisesRegex(ValueError, 'cannot resume'):
            self.sample(0)

    def test_later_wrong_trace_scope_refuses(self):
        self.sample(0)
        with self.assertRaises(ValueError):
            self.window.sample(0, dict(process_id=100,
                                      contact_trace=self.traces[1].snapshot()), now=2)
        self.assertTrue(self.window.failed)

    def test_evicted_intervals_cannot_be_reported_as_complete(self):
        for _ in range(MAX_EVENTS + 1):
            self.traces[0].event('contact_start')
        self.assertFalse(self.sample(0)['this_interval_complete'])
        self.assertFalse(self.window.snapshot()['intervals_complete'][0])
        self.sample(0)
        self.assertFalse(self.window.snapshot()['intervals_complete'][0])

    def test_deadline_is_original_absolute_bound_without_grace(self):
        for now in (180, float('inf'), float('nan')):
            with self.subTest(now=now):
                window = TraceWindow(self.network, self.slots, deadline=180)
                with self.assertRaisesRegex(ValueError, 'deadline'):
                    window.sample(0, self.status(0), now=now)
                self.assertTrue(window.failed)

    def test_event_and_byte_capacity_refuse_without_reusing_advanced_cursor(self):
        self.traces[0].event('contact_start')
        for name, value in (('MAX_WINDOW_EVENTS', 0), ('MAX_WINDOW_BYTES', 1)):
            with self.subTest(name=name), patch('regional_contact_trace_window.' + name, value):
                window = TraceWindow(self.network, self.slots, deadline=180)
                with self.assertRaisesRegex(ValueError, 'capacity'):
                    window.sample(0, self.status(0), now=1)
                self.assertTrue(window.failed)
                self.assertEqual(window.events, [])

    def test_incremental_bytes_equal_complete_canonical_rows(self):
        for turn in range(5):
            for i in range(4):
                self.traces[i].event('contact_start')
                self.sample(i)
                self.assertEqual(self.window.event_bytes, len(wire.canonical(self.window.events)))
        with patch('regional_contact_trace_window.wire.canonical', wraps=wire.canonical) as encode:
            self.sample(0)  # Empty delta must not re-encode the accumulated history.
            self.assertFalse(any(call.args[0] is self.window.events for call in encode.call_args_list))

    def controller(self):
        return SimpleNamespace(processes={('proxima', i): SimpleNamespace(pid=100+i, poll=lambda: None)
                    for i in range(4)}, pins=[{'node_id': self.slots[i][1]} for i in range(4)],
                    currency=self.network, deadline=180,
                    transport=[{'state': str(Path('/synthetic-never-opened') / str(i))} for i in range(4)],
                    remaining=lambda: 1)

    def test_actual_driver_hook_reads_four_statuses_and_only_scalar_deltas(self):
        controller = self.controller(); window = TraceWindow.attach(controller)
        for trace in self.traces.values(): trace.event('request_sent', nonce='d'*64)
        def read(path): return self.status(int(path.parent.name))
        with patch('regional_paged_fault_scope.document', side_effect=read) as read_status, \
                patch('regional_contact_trace_window.time.monotonic', return_value=1):
            window.collect(controller)
            self.assertEqual(read_status.call_count, 4)
        self.assertTrue(window.snapshot()['all_four_streams_observed'])
        self.assertEqual(len(window.events), 4)
        self.assertNotIn('never-retain', str(window.snapshot()))

    def test_exit_missing_status_and_read_error_are_not_success_or_recovery(self):
        for mode in ('exit', 'missing', 'damaged'):
            controller = self.controller(); window = TraceWindow.attach(controller)
            if mode == 'exit': controller.processes['proxima', 0].poll = lambda: 1
            failure = FileNotFoundError() if mode == 'missing' else ValueError('damaged trace')
            with patch('regional_paged_fault_scope.document', side_effect=failure), \
                    patch('regional_contact_trace_window.time.monotonic', return_value=1):
                if mode == 'missing':
                    window.collect(controller)
                    self.assertEqual(window.unknown, {i: 1 for i in range(4)})
                    self.assertFalse(window.snapshot()['all_four_streams_observed'])
                else:
                    with self.assertRaises(ValueError): window.collect(controller)
                    self.assertTrue(window.failed)
            self.assertEqual(window.events, [])

    def test_exact_four_distinct_owned_slots_required(self):
        for slots in ({0: self.slots[0]}, {i: self.slots[0] for i in range(4)}):
            with self.assertRaises(ValueError):
                TraceWindow(self.network, slots, deadline=180)


if __name__ == '__main__':
    unittest.main()
