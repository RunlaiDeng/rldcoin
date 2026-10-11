"""Real custody boundaries and bounded scheduling; no Native authority."""
from contextlib import nullcontext
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_tcp as tcp
from regional_receive_wake import Wait, MIN_IDLE_INTERVAL
from test_interstellar_tcp import Fixture


class ReceiveWakeTests(unittest.TestCase):
    def fixture(self):
        parent=Path(os.environ.get('RLD_RETAINED_GROUND_ROOT',str(Path(__file__).resolve().parents[1]/'tmp'))).resolve()
        parent.mkdir(parents=True,exist_ok=True)
        fixture=Fixture(tempfile.mkdtemp(prefix='rld-receive-wake-',dir=parent),names=('earth','proxima'))
        self.addCleanup(fixture.close)
        return fixture

    def waiter(self,server,interval=1.0):
        wait=Wait(server,interval);self.addCleanup(wait.close);return wait

    def test_actual_TLS_new_input_wakes_after_close_without_duplicate_notice(self):
        fixture=self.fixture();server=fixture.servers['proxima'];wait=self.waiter(server)
        notices=[];original=server.notify_received
        def notice():
            self.assertIsNone(server.local_mesh_owner)
            with mesh.Node(server.config,nonblocking=True) as node:
                notices.append(set(node.state['messages']))
                self.assertFalse(node.status()['payment_authorized'])
            original()
        ready=threading.Event();finished=[]
        def consume():
            ready.set();finished.append((wait.wait(lambda:True),time.monotonic()))
        thread=threading.Thread(target=consume);started=time.monotonic();thread.start()
        self.assertTrue(ready.wait(1))
        with fixture.node('earth') as node:packet=node.enqueue(fixture.frame(),fixture.ids['proxima'])
        with patch.object(server,'notify_received',side_effect=notice):
            report=fixture.servers['earth'].tick();thread.join(2)
            self.assertFalse(thread.is_alive());self.assertFalse(report['errors'])
            self.assertTrue(finished[0][0]);self.assertLess(finished[0][1]-started,.8)
            self.assertGreaterEqual(finished[0][1]-started,MIN_IDLE_INTERVAL-.001)
            self.assertEqual(notices,[{packet}]);self.assertFalse(wait.pending)
            fixture.servers['earth'].tick()
            self.assertEqual(notices,[{packet}]);self.assertFalse(wait.pending)
        with fixture.node('proxima') as node:self.assertIn(packet,node.receipts())

    def test_receive_write_body_and_close_refusals_never_notify(self):
        for failure in ('write','body','close'):
            with self.subTest(failure=failure):
                fixture=self.fixture();server=fixture.servers['proxima'];wait=self.waiter(server)
                with fixture.node('earth') as node:
                    packet=node.enqueue(fixture.frame(),fixture.ids['proxima'])
                    bundle=tcp.outgoing(node,fixture.ids['proxima'])
                original=mesh.Node.close
                def refused_close(node):original(node);raise OSError('controlled close refusal')
                close_patch=patch.object(mesh.Node,'close',autospec=True,side_effect=refused_close) if failure=='close' else nullcontext()
                with self.assertRaises(OSError),close_patch:
                    with server.mesh_node(time.monotonic()+tcp.ATTEMPT_SECONDS) as node:
                        if failure=='write':
                            with patch.object(mesh,'atomic',side_effect=OSError('write refused')):node.receive(bundle,fixture.ids['earth'])
                        else:
                            node.receive(bundle,fixture.ids['earth'])
                            if failure=='body':raise OSError('body refused')
                self.assertFalse(wait.pending);self.assertIsNone(server.local_mesh_owner)
                if failure!='write':
                    with fixture.node('proxima') as node:self.assertIn(packet,node.receipts())

    def test_failed_notice_keeps_actual_receipt_and_periodic_fallback(self):
        fixture=self.fixture();server=fixture.servers['proxima']
        def fail():raise OSError('notice refused')
        server.claim_receive_wake(fail);self.addCleanup(lambda:server.release_receive_wake(fail))
        with fixture.node('earth') as node:packet=node.enqueue(fixture.frame(),fixture.ids['proxima'])
        self.assertFalse(fixture.servers['earth'].tick()['errors'])
        self.assertEqual(server.report()['receive_wake_failures'],1)
        with fixture.node('proxima') as node:self.assertIn(packet,node.receipts())

    def test_pending_notice_storm_preserves_minimum_idle_and_coalesces(self):
        fixture=self.fixture();wait=self.waiter(fixture.servers['proxima'])
        for _ in range(1000):wait.notify()
        started=time.monotonic();self.assertTrue(wait.wait(lambda:True));elapsed=time.monotonic()-started
        self.assertGreaterEqual(elapsed,MIN_IDLE_INTERVAL-.001);self.assertLess(elapsed,.5)
        self.assertFalse(wait.pending)
        for _ in range(1000):wait.notify()
        started=time.monotonic();self.assertTrue(wait.wait(lambda:True))
        self.assertGreaterEqual(time.monotonic()-started,MIN_IDLE_INTERVAL-.001)

    def test_periodic_fallback_runs_without_a_notice(self):
        fixture=self.fixture();wait=self.waiter(fixture.servers['proxima'],.15)
        started=time.monotonic();self.assertFalse(wait.wait(lambda:True))
        self.assertGreaterEqual(time.monotonic()-started,.15-.001)
        self.assertLess(time.monotonic()-started,.5)

    def test_stop_interrupts_long_wait_and_late_callback_cannot_restart(self):
        fixture=self.fixture();server=fixture.servers['proxima'];wait=self.waiter(server,3600)
        callback=wait.callback;entered=threading.Event();finished=[]
        def consume():entered.set();finished.append(wait.wait(lambda:True))
        thread=threading.Thread(target=consume);thread.start();self.assertTrue(entered.wait(1))
        wait.close();thread.join(1);self.assertFalse(thread.is_alive());self.assertEqual(finished,[False])
        callback();wait.close();self.assertIsNone(server.receive_wake);self.assertFalse(wait.pending)

    def test_second_owner_refuses_without_replacing_original_callback(self):
        fixture=self.fixture();server=fixture.servers['proxima'];wait=self.waiter(server)
        with self.assertRaises(ValueError):Wait(server,.25)
        self.assertIs(server.receive_wake,wait.callback)


if __name__=='__main__':unittest.main()
