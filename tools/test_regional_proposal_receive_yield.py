"""Durable-input scheduling boundaries; models never authorize Native value."""
import os
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import bft_tick_fixture as baseline
import regional_contact_node as contact
import test_regional_initial_phase_wait as initial
from regional_receive_wake import Wait,YIELD_FOR_DURABLE_INPUT,MIN_IDLE_INTERVAL
from test_interstellar_tcp import Fixture


class CallbackOwner:
    running=True
    def claim_receive_wake(self,callback):self.receive_wake=callback
    def release_receive_wake(self,callback):
        if self.receive_wake is not callback:raise ValueError('foreign callback')
        self.receive_wake=None


class ProposalReceiveYieldTests(unittest.TestCase):
    def service(self):
        server=CallbackOwner();owner=Wait(server,1.);self.addCleanup(owner.close)
        service=contact.Service.__new__(contact.Service);service.tcp=server
        service.proposal_receive_wait=owner
        return service,owner

    def test_notice_yields_without_intake_or_consuming_the_next_unit_notice(self):
        service,owner=self.service();owner.notify();late=[]
        due=time.monotonic()+.5
        self.assertIs(service.wait_initial_proposal(due,lambda:late.append(True)),YIELD_FOR_DURABLE_INPUT)
        self.assertLess(time.monotonic(),due);self.assertEqual(late,[])
        for _ in range(1000):self.assertTrue(owner.has_pending())
        self.assertTrue(owner.pending)
        started=time.monotonic();self.assertTrue(owner.wait(lambda:True))
        self.assertGreaterEqual(time.monotonic()-started,MIN_IDLE_INTERVAL-.001)
        self.assertFalse(owner.pending)

    def test_due_reached_keeps_original_single_late_intake(self):
        service,owner=self.service();owner.notify();late=[]
        with patch.object(contact.time,'monotonic',return_value=2.):
            self.assertIs(service.wait_initial_proposal(2.,lambda:late.append(True)),True)
        self.assertEqual(late,[True]);self.assertTrue(owner.pending)

    def test_foreign_closed_stopped_and_missing_owner_keep_original_due(self):
        for kind in ('foreign','closed','stopped','missing'):
            service,owner=self.service();owner.notify();now=[1.];late=[]
            if kind=='foreign':service.tcp=CallbackOwner()
            elif kind=='closed':owner.close()
            elif kind=='stopped':owner.stop()
            else:service.proposal_receive_wait=None
            def sleep(seconds):now[0]+=seconds
            with patch.object(contact.time,'monotonic',side_effect=lambda:now[0]), \
                 patch.object(contact.time,'sleep',side_effect=sleep):
                self.assertIs(service.wait_initial_proposal(1.25,lambda:late.append(now[0])),True)
            self.assertEqual(late,[1.25])

    def test_out_of_bound_and_stop_never_yield_or_take_intake(self):
        service,owner=self.service();owner.notify();late=[]
        with patch.object(contact.time,'monotonic',return_value=1.):
            self.assertFalse(service.wait_initial_proposal(2.1,lambda:late.append(True)))
            self.assertFalse(service.wait_initial_proposal(float('nan'),lambda:late.append(True)))
            service.tcp.running=False
            with self.assertRaises(contact.tcp.MeshRuntimeStopping):
                service.wait_initial_proposal(1.5,lambda:late.append(True))
        self.assertEqual(late,[])

    def test_notice_arrival_returns_the_wait_without_a_new_worker_or_callback(self):
        service,owner=self.service();entered=threading.Event();results=[];late=[]
        def run():entered.set();results.append(service.wait_initial_proposal(time.monotonic()+.8,lambda:late.append(True)))
        thread=threading.Thread(target=run);thread.start();self.assertTrue(entered.wait(1))
        callback=service.tcp.receive_wake;owner.notify();thread.join(1)
        self.assertFalse(thread.is_alive());self.assertEqual(results,[YIELD_FOR_DURABLE_INPUT])
        self.assertEqual(late,[]);self.assertIs(service.tcp.receive_wake,callback);self.assertTrue(owner.pending)

    def test_runtime_yield_cannot_first_sign_even_when_return_crosses_original_due(self):
        runtime=initial.InitialPhaseWaitTests().runtime();reads=[];original=runtime.loop_observation
        runtime.loop_observation=lambda:reads.append(True) or original()
        def wait(due):
            self.assertEqual(due,2.);baseline.clock.now=due+.01
            return YIELD_FOR_DURABLE_INPUT
        runtime.before_initial_proposal=wait;runtime.tick()
        self.assertEqual(runtime.requests,[]);self.assertEqual(len(reads),1)
        self.assertEqual(runtime.entered_at,1.);self.assertEqual(runtime._phase_context_started[1],1.)
        self.assertIsNone(runtime._tick_operation);self.assertIsNone(runtime.head['pending'])

    def test_next_runtime_unit_reopens_native_and_refuses_changed_caller_head(self):
        runtime=initial.InitialPhaseWaitTests().runtime();runtime.before_initial_proposal=lambda due:YIELD_FOR_DURABLE_INPUT
        runtime.tick();self.assertEqual(runtime.requests,[])
        baseline.clock.now=2.01
        runtime.loop_observation=lambda:(_ for _ in ()).throw(ValueError('current caller head refused'))
        with self.assertRaisesRegex(ValueError,'current caller head refused'):runtime.tick()
        self.assertEqual(runtime.requests,[]);self.assertIsNone(runtime.head['pending'])

    def test_next_runtime_unit_uses_original_due_without_restarting_phase_clock(self):
        runtime=initial.InitialPhaseWaitTests().runtime();runtime.before_initial_proposal=lambda due:YIELD_FOR_DURABLE_INPUT
        runtime.tick();self.assertEqual(runtime.requests,[])
        baseline.clock.now=2.01;runtime.tick()
        self.assertEqual(runtime.requests,[dict(kind='Propose',round=0)])
        self.assertEqual(runtime._phase_context_started[1],1.)

    def test_yield_publication_refusal_preserves_original_failure(self):
        runtime=initial.InitialPhaseWaitTests().runtime();runtime.before_initial_proposal=lambda due:YIELD_FOR_DURABLE_INPUT
        runtime.broadcast=lambda:(_ for _ in ()).throw(OSError('complete carriage close refused'))
        with self.assertRaisesRegex(OSError,'complete carriage close refused'):runtime.tick()
        self.assertEqual(runtime.requests,[]);self.assertIsNone(runtime._tick_operation)

    def test_actual_pinned_TLS_custody_yields_wait_then_keeps_minimum_idle(self):
        parent=Path(os.environ.get('RLD_RETAINED_GROUND_ROOT',str(Path(__file__).resolve().parents[1]/'tmp'))).resolve()
        parent.mkdir(parents=True,exist_ok=True)
        fixture=Fixture(tempfile.mkdtemp(prefix='rld-proposal-input-yield-',dir=parent),names=('earth','proxima'))
        self.addCleanup(fixture.close);server=fixture.servers['proxima'];owner=Wait(server,1.);self.addCleanup(owner.close)
        service=contact.Service.__new__(contact.Service);service.tcp=server;service.proposal_receive_wait=owner
        results=[];late=[];entered=threading.Event();due=time.monotonic()+.8
        def run():entered.set();results.append(service.wait_initial_proposal(due,lambda:late.append(True)))
        thread=threading.Thread(target=run);thread.start();self.assertTrue(entered.wait(1))
        with fixture.node('earth') as node:packet=node.enqueue(fixture.frame(),fixture.ids['proxima'])
        self.assertFalse(fixture.servers['earth'].tick()['errors']);thread.join(1)
        self.assertFalse(thread.is_alive());self.assertEqual(results,[YIELD_FOR_DURABLE_INPUT]);self.assertEqual(late,[])
        self.assertIsNone(server.local_mesh_owner);self.assertTrue(owner.pending)
        with fixture.node('proxima') as node:self.assertIn(packet,node.receipts())
        started=time.monotonic();self.assertTrue(owner.wait(lambda:True))
        self.assertGreaterEqual(time.monotonic()-started,MIN_IDLE_INTERVAL-.001)
        self.assertFalse(fixture.servers['earth'].tick()['errors']);self.assertFalse(owner.pending)


if __name__=='__main__':unittest.main()
