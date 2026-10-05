"""Lease timing preserves original ownership, errors and acquisition bounds."""
import errno
import threading
import unittest
from unittest.mock import patch

import interstellar_tcp as tcp
import interstellar_transfer as wire
from interstellar_mesh_cost import MeshCosts, MAX_COUNT, MAX_SECONDS, MAX_BYTES


class Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class LeaseCostsTests(unittest.TestCase):
    def run_path(self, measured=True, failure=None, busy=False, ordinary=True):
        clock = Clock()
        order = []

        class Node:
            def __init__(self, config, nonblocking):
                self_outer.assertEqual((config, nonblocking), ('synthetic-never-opened', True))
                order.append('open')
                clock.now += .35
                if failure == 'open':
                    raise ValueError('open refused')

            def close(self):
                order.append('close')
                clock.now += .07
                if failure == 'close':
                    raise ValueError('close refused')

        self_outer = self
        server = tcp.Server.__new__(tcp.Server)
        server.guard = threading.Lock()
        server.running = True
        server.config = 'synthetic-never-opened'
        server.selection_owner = server.selection_purpose = server.selection_attempt_owner = None
        server.selection_preference_until = 0.0
        server.local_mesh_owner = object() if busy else None
        server.last_mesh_class = server.last_tcp_role = None
        server.tcp_mesh_waiters = set()
        server.local_lock_retries = server.local_lock_exhaustions = 0
        server.outbound_owner = None
        if measured:
            server.mesh_costs = MeshCosts()
        error = None
        with patch.object(tcp.time, 'monotonic', clock.monotonic), \
                patch.object(tcp.time, 'sleep', clock.sleep), patch.object(tcp.mesh, 'Node', Node):
            if ordinary:
                server.request_selection('receive')
            try:
                with server._local_mesh_node(clock.now + .2 if ordinary else 3.0, ordinary):
                    order.append('body')
                    clock.now += .1
                    if failure == 'body':
                        raise ValueError('body refused')
            except (ValueError, BlockingIOError) as caught:
                error = caught
        return server, order, error, clock.now

    def test_success_does_not_extend_acquisition_wait_or_bound_validation_cpu(self):
        server, order, error, duration = self.run_path()
        self.assertEqual(order, ['open', 'body', 'close'])
        self.assertIsNone(error)
        self.assertAlmostEqual(duration, .52)
        rows = server.mesh_costs.snapshot()['rows']['receive']
        self.assertEqual(rows['open']['last_seconds'], .35)
        self.assertEqual(rows['acquire']['last_seconds'], .35)
        self.assertEqual(rows['hold']['last_seconds'], .52)
        self.assertIsNone(server.local_mesh_owner)
        self.assertIsNone(server.selection_attempt_owner)
        self.assertIs(server.selection_owner, threading.current_thread())

    def test_each_failure_preserves_exact_original_order_and_ownership(self):
        for failure in ('open', 'body', 'close'):
            with self.subTest(failure=failure):
                measured = self.run_path(failure=failure)
                original = self.run_path(measured=False, failure=failure)
                self.assertEqual(measured[1], original[1])
                self.assertEqual(str(measured[2]), str(original[2]))
                self.assertEqual(measured[3], original[3])
                self.assertIsNone(measured[0].local_mesh_owner)
                self.assertIsNone(measured[0].selection_attempt_owner)
                if failure == 'close':
                    self.assertEqual(measured[0].mesh_costs.snapshot()['rows']['receive']['hold']['failures'], 1)

    def test_real_bound_refusal_records_no_open_or_hold_and_retains_purpose(self):
        server, order, error, duration = self.run_path(busy=True)
        self.assertEqual(order, [])
        self.assertIsInstance(error, BlockingIOError)
        self.assertEqual(error.errno, errno.EAGAIN)
        self.assertAlmostEqual(duration, tcp.MAX_LOCAL_LOCK_WAIT_SECONDS)
        rows = server.mesh_costs.snapshot()['rows']['receive']
        self.assertEqual(rows['acquire']['failures'], 1)
        self.assertEqual(rows['open']['calls'], 0)
        self.assertEqual(rows['hold']['calls'], 0)
        self.assertEqual(server.selection_purpose, 'receive')

    def test_other_purpose_refusal_still_preserves_original_owner(self):
        server, _, _, _ = self.run_path()
        with self.assertRaises(BlockingIOError):
            server.request_selection('carriage')
        self.assertEqual(server.selection_purpose, 'receive')
        self.assertEqual(server.mesh_costs.snapshot()['rows']['carriage']['purpose']['failures'], 1)
        server.finish_selection()
        server.request_selection('carriage')
        self.assertEqual(server.mesh_costs.snapshot()['rows']['carriage']['purpose']['calls'], 2)

    def test_tcp_role_costs_have_no_ordinary_purpose_or_custody_grant(self):
        server, _, error, _ = self.run_path(ordinary=False)
        self.assertIsNone(error)
        snapshot = server.mesh_costs.snapshot()
        self.assertEqual(snapshot['rows']['tcp-handler']['hold']['calls'], 1)
        self.assertFalse(snapshot['timing_is_authority'])
        self.assertEqual(snapshot['rows']['receive']['acquire']['calls'], 0)
        self.assertIsNone(server.selection_owner)
        self.assertEqual(server.tcp_mesh_waiters, set())

    def test_fixed_capacity_saturation_snapshot_isolation_and_restart(self):
        costs = MeshCosts()
        costs.record('receive', 'open', MAX_SECONDS * 2, False)
        costs.rows['receive', 'open']['calls'] = MAX_COUNT
        costs.record('receive', 'open', 1., True)
        first = costs.snapshot()
        self.assertTrue(first['rows']['receive']['open']['saturated'])
        self.assertEqual(first['rows']['receive']['open']['calls'], MAX_COUNT)
        self.assertLessEqual(len(wire.canonical(first)), MAX_BYTES)
        first['rows']['receive']['open']['calls'] = 0
        self.assertEqual(costs.snapshot()['rows']['receive']['open']['calls'], MAX_COUNT)
        self.assertEqual(MeshCosts().snapshot()['rows']['receive']['open']['calls'], 0)
        for role, stage, duration in [({}, 'open', 1.), ('peer-secret', 'open', 1.),
                                      ('receive', 'mutable', {}), ('receive', 'open', float('nan'))]:
            costs.record(role, stage, duration, True)
        self.assertEqual(len(costs.rows), 20)

    def test_parallel_observations_are_exact_and_bounded(self):
        costs = MeshCosts()
        threads = [threading.Thread(target=lambda: [costs.record('tcp-input', 'hold', .1, True)
                                                    for _ in range(100)]) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
            self.assertFalse(thread.is_alive())
        snapshot = costs.snapshot()
        self.assertEqual(snapshot['rows']['tcp-input']['hold']['calls'], 400)
        self.assertLessEqual(len(wire.canonical(snapshot)), MAX_BYTES)


if __name__ == '__main__':
    unittest.main()
