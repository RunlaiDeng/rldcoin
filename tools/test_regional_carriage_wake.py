"""Coalesced wake schedules existing capacity; no payment or custody authority."""
import tempfile
from contextlib import nullcontext
import os
from pathlib import Path
import threading
import time
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
from regional_carriage_worker import Worker,MIN_WAKE_INTERVAL
from test_interstellar_tcp import Fixture


class Server:
    def __init__(self,blocked=False):
        self.running=True;self.owner=None;self.callback=None;self.starts=[]
        self.first=threading.Event();self.second=threading.Event();self.release=threading.Event()
        if not blocked:self.release.set()
    def claim_outbound(self,owner,*,wake=None):
        assert self.owner is None;self.owner=owner;self.callback=wake
    def release_outbound(self,owner):
        assert self.owner is owner and not owner.is_alive();self.owner=self.callback=None
    def tick(self):
        assert self.owner is threading.current_thread()
        self.starts.append(time.monotonic())
        if len(self.starts)==1:self.first.set();assert self.release.wait(3)
        if len(self.starts)==2:self.second.set()
        return dict(no_value=True)
    def observation(self):return dict(no_value=True)


class WakeTests(unittest.TestCase):
    def test_notifications_during_pass_merge_without_exceeding_start_rate(self):
        server=Server(blocked=True);worker=Worker(server,1.0)
        try:
            self.assertTrue(server.first.wait(2))
            for _ in range(1000):server.callback()
            server.release.set();self.assertTrue(server.second.wait(.8))
            self.assertGreaterEqual(server.starts[1]-server.starts[0],MIN_WAKE_INTERVAL-.001)
            self.assertLess(server.starts[1]-server.starts[0],.8)
            time.sleep(.03);self.assertEqual(len(server.starts),2)
            self.assertEqual(worker.interval,1.0)
        finally:server.release.set();worker.close()
        self.assertIsNone(server.owner)

    def test_continuous_notifications_still_bound_original_minimum_interval(self):
        server=Server();worker=Worker(server,1.0)
        try:
            self.assertTrue(server.first.wait(2));until=time.monotonic()+.32
            while time.monotonic()<until:worker.notify();time.sleep(.001)
            self.assertGreaterEqual(len(server.starts),3)
            for a,b in zip(server.starts,server.starts[1:]):
                self.assertGreaterEqual(b-a,MIN_WAKE_INTERVAL-.001)
        finally:worker.close()

    def test_close_interrupts_long_poll_and_old_callback_cannot_restart(self):
        server=Server();worker=Worker(server,3600)
        self.assertTrue(server.first.wait(2));callback=server.callback
        started=time.monotonic();worker.close()
        self.assertLess(time.monotonic()-started,.5)
        before=len(server.starts);callback();worker.close()
        self.assertEqual(len(server.starts),before)
        self.assertFalse(worker.thread.is_alive());self.assertIsNone(server.callback)

    def fixture(self):
        parent=Path(os.environ.get('RLD_RETAINED_GROUND_ROOT',
                    str(Path(__file__).resolve().parents[1]/'tmp'))).resolve()
        parent.mkdir(parents=True,exist_ok=True)
        # Fresh private no-value stores are retained even when a test refuses.
        root=tempfile.mkdtemp(prefix='rld-carriage-wake-',dir=parent)
        fixture=Fixture(root,names=('earth','proxima'))
        self.addCleanup(fixture.close)
        return fixture

    def register(self,server,callback):
        owner=threading.Thread(target=lambda:None)
        server.claim_outbound(owner,wake=callback)
        self.addCleanup(lambda:server.release_outbound(owner) if server.outbound_owner is owner else None)

    def test_new_enqueue_notifies_only_after_full_close_and_lease_release(self):
        fixture=self.fixture();server=fixture.servers['earth'];observed=[]
        def notify():
            self.assertIsNone(server.local_mesh_owner);self.assertIsNone(server.selection_owner)
            with mesh.Node(server.config,nonblocking=True) as node:
                observed.append(set(node.state['messages']))
        self.register(server,notify)
        with server.ordinary_mesh_node() as node:
            packet=node.enqueue(fixture.frame(),fixture.ids['proxima'])
            self.assertEqual(observed,[])
        self.assertEqual(observed,[{packet}])
        with server.ordinary_mesh_node() as node:
            self.assertIn(packet,node.state['messages'])
            node.save()  # exact retained IDs do not request another wake
        self.assertEqual(len(observed),1)

    def test_failed_write_body_or_close_does_not_notify_or_remove_evidence(self):
        for failure in ('write','body','close'):
            with self.subTest(failure=failure):
                fixture=self.fixture();server=fixture.servers['earth'];observed=[]
                self.register(server,lambda:observed.append(True));packet=None
                original=mesh.Node.close
                def close(node):original(node);raise OSError('close refused')
                with self.assertRaises(OSError):
                    with patch.object(mesh.Node,'close',side_effect=close,autospec=True) if failure=='close' else nullcontext():
                        with server.ordinary_mesh_node() as node:
                            if failure=='write':
                                with patch.object(mesh,'atomic',side_effect=OSError('write refused')):
                                    node.enqueue(fixture.frame(),fixture.ids['proxima'])
                            else:
                                packet=node.enqueue(fixture.frame(),fixture.ids['proxima'])
                                if failure=='body':raise OSError('body refused')
                self.assertEqual(observed,[])
                self.assertIsNone(server.local_mesh_owner);self.assertIsNone(server.selection_owner)
                if packet is not None:
                    with fixture.node('earth') as node:self.assertIn(packet,node.state['messages'])

    def test_failed_wake_retains_queue_and_periodic_transport_fallback(self):
        fixture=self.fixture();server=fixture.servers['earth']
        def refused():raise OSError('wake refused')
        self.register(server,refused)
        with server.ordinary_mesh_node() as node:packet=node.enqueue(fixture.frame(),fixture.ids['proxima'])
        self.assertEqual(server.report()['outbound_wake_failures'],1)
        # The test owner is not a live worker. Release it through the existing
        # guard, then use the unchanged ordinary pinned TLS path.
        owner=server.outbound_owner;server.release_outbound(owner)
        fixture.rounds(2)
        with fixture.node('proxima') as node:
            self.assertIn(packet,node.receipts());self.assertFalse(node.status()['payment_authorized'])


if __name__=='__main__':unittest.main()
