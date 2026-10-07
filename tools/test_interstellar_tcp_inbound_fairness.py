"""Actual retained-input demand alternates with handlers without custody rights."""
import errno
import threading
import unittest
from unittest.mock import patch
import interstellar_tcp as tcp

class Actor:
    def __init__(self, name, alive=True):
        self.name, self.alive = name, alive
    def is_alive(self):
        return self.alive

class Clock:
    now = 0.0
    def monotonic(self):
        return self.now
    def sleep(self, duration):
        self.now += duration

class Node:
    def __init__(self, config, nonblocking):
        assert config == 'synthetic-no-custody' and nonblocking
    def close(self):
        pass

class InboundFairnessTests(unittest.TestCase):
    def setup(self):
        server = tcp.Server.__new__(tcp.Server)
        server.guard = threading.Lock()
        server.input_wake = threading.Event()
        server.running = True
        server.config = 'synthetic-no-custody'
        server.selection_owner = server.selection_purpose = server.selection_attempt_owner = None
        server.selection_preference_until = 0.0
        server.local_mesh_owner = None
        server.last_mesh_class = server.last_tcp_role = server.last_tcp_inbound_role = None
        server.tcp_mesh_waiters = set()
        server.local_lock_retries = server.local_lock_exhaustions = 0
        server.outbound_owner = Actor('outbound')
        server.input_thread = Actor('retained-input')
        server.input_active = ('synthetic-unacknowledged-original',)
        clock = Clock()
        for obj, name, value in ((tcp.mesh, 'Node', Node), (tcp.time, 'monotonic', clock.monotonic),
                                 (tcp.time, 'sleep', clock.sleep)):
            context = patch.object(obj, name, value)
            context.start()
            self.addCleanup(context.stop)
        return server, clock

    def turn(self, server, clock, actor):
        with patch.object(tcp.threading, 'current_thread', return_value=actor):
            try:
                with server._local_mesh_node(clock.now + 3, False):
                    return True
            except BlockingIOError:
                return False

    def test_continuous_new_handlers_cannot_starve_retained_input(self):
        server, clock = self.setup()
        successes = {'outbound': 0, 'handler': 0, 'input': 0}
        last_input_round = -1
        for index in range(32):
            handler = Actor('fresh-handler-' + str(index))
            server.tcp_mesh_waiters.update((server.input_thread, handler))
            for actor, key in ((server.outbound_owner, 'outbound'), (handler, 'handler'),
                               (server.input_thread, 'input')):
                if actor is handler:
                    server.tcp_mesh_waiters.add(server.outbound_owner)
                if self.turn(server, clock, actor):
                    successes[key] += 1
                    if key == 'input':
                        self.assertLessEqual(index - last_input_round, 2)
                        last_input_round = index
            self.assertIsNone(server.local_mesh_owner)
            self.assertEqual(server.input_active, ('synthetic-unacknowledged-original',))
        self.assertEqual(successes, {'outbound': 32, 'handler': 16, 'input': 16})
        self.assertEqual(tcp.MAX_LOCAL_LOCK_WAIT_SECONDS, .2)

    def test_retained_input_and_handler_both_get_inbound_turns(self):
        server, clock = self.setup()
        handler = Actor('handler')
        server.tcp_mesh_waiters.update((server.input_thread, handler))
        self.assertFalse(self.turn(server, clock, handler))
        self.assertTrue(self.turn(server, clock, server.input_thread))
        server.tcp_mesh_waiters.update((server.input_thread, handler))
        self.assertFalse(self.turn(server, clock, server.input_thread))
        self.assertTrue(self.turn(server, clock, handler))
        server.tcp_mesh_waiters.add(server.input_thread)
        self.assertTrue(self.turn(server, clock, server.input_thread))

    def test_absent_job_or_dead_input_does_not_block_handlers(self):
        for active, alive in ((None, True), (('synthetic',), False)):
            server, clock = self.setup()
            server.input_active = active
            server.input_thread.alive = alive
            server.tcp_mesh_waiters.add(server.input_thread)
            self.assertTrue(self.turn(server, clock, Actor('handler')))

    def test_open_refusal_never_consumes_inbound_turn(self):
        server, clock = self.setup()
        with patch.object(tcp.mesh, 'Node', side_effect=ValueError('full authentication refused')):
            with self.assertRaisesRegex(ValueError, 'authentication refused'):
                self.turn(server, clock, server.input_thread)
        self.assertIsNone(server.last_tcp_inbound_role)
        self.assertIsNone(server.local_mesh_owner)
        self.assertEqual(server.input_active, ('synthetic-unacknowledged-original',))

    def test_os_lock_refusal_retains_original_job_and_bound(self):
        server, clock = self.setup()
        with patch.object(tcp.mesh, 'Node', side_effect=BlockingIOError(errno.EAGAIN, 'busy')):
            self.assertFalse(self.turn(server, clock, server.input_thread))
        self.assertAlmostEqual(clock.now, .2)
        self.assertIn(server.input_thread, server.tcp_mesh_waiters)
        self.assertIsNone(server.last_tcp_inbound_role)
        self.assertIsNone(server.local_mesh_owner)
        self.assertEqual(server.input_active, ('synthetic-unacknowledged-original',))

if __name__ == '__main__':
    unittest.main()
