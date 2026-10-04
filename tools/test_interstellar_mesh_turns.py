"""Real local mesh admissions and TLS; scheduling never grants custody."""
import errno
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_tcp as tcp
from regional_contact_node import Service
from test_interstellar_tcp import Fixture


class MeshTurnTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.f=Fixture(self.temp.name,names=('earth','proxima'));self.addCleanup(self.f.close)
        self.server=self.f.servers['earth']

    def foreign(self, action):
        result=[]
        def run():
            try:result.append(action())
            except BaseException as error:result.append(error)
        thread=threading.Thread(target=run);thread.start();thread.join(5)
        self.assertFalse(thread.is_alive());return result[0]

    def selection(self):
        self.server.request_selection()
        try:
            with self.server.selection_mesh_node(time.monotonic()+tcp.MAX_LOCAL_LOCK_WAIT_SECONDS) as node:
                self.assertEqual(node.id,self.f.ids['earth'])
        finally:self.server.finish_selection()

    def tcp_open(self):
        with self.server.mesh_node(time.monotonic()+tcp.ATTEMPT_SECONDS) as node:return node.id

    def test_repeated_foreground_requests_allow_tcp_then_reclaim_ordinary_turn(self):
        self.selection();self.server.request_selection()
        self.assertEqual(self.foreign(self.tcp_open),self.f.ids['earth'])
        blocked=self.foreign(self.tcp_open)
        self.assertIsInstance(blocked,BlockingIOError);self.assertEqual(blocked.errno,errno.EAGAIN)
        with self.server.selection_mesh_node(time.monotonic()+tcp.MAX_LOCAL_LOCK_WAIT_SECONDS):pass
        self.server.finish_selection()
        self.assertIsNone(self.server.local_mesh_owner)

    def test_service_selection_allows_tcp_before_its_next_pending_selection(self):
        service=Service.__new__(Service);service.tcp=self.server;service.config=self.f.configs['earth']
        with service.selection_node() as node:self.assertEqual(node.id,self.f.ids['earth'])
        self.server.request_selection()
        try:self.assertEqual(self.foreign(self.tcp_open),self.f.ids['earth'])
        finally:self.server.finish_selection()

    def test_actual_outgoing_owner_retains_timeout_demand_and_cannot_be_starved_by_next_selection(self):
        attempted=threading.Event();resume=threading.Event();results=[]
        self.server.request_selection()
        def outgoing():
            try:
                try:self.tcp_open()
                except BlockingIOError:results.append('bounded refusal')
                attempted.set();resume.wait(5)
                results.append(self.tcp_open())
            except BaseException as error:results.append(error)
        thread=threading.Thread(target=outgoing);self.server.claim_outbound(thread);thread.start()
        try:
            self.assertTrue(attempted.wait(5));self.assertIn(thread,self.server.tcp_mesh_waiters)
            with self.server.selection_mesh_node(time.monotonic()+tcp.MAX_LOCAL_LOCK_WAIT_SECONDS):pass
            self.server.finish_selection();self.server.request_selection()
            with self.assertRaises(BlockingIOError):
                with self.server.selection_mesh_node(time.monotonic()+tcp.MAX_LOCAL_LOCK_WAIT_SECONDS):self.fail('TCP demand bypassed')
            self.assertIs(self.server.selection_owner,threading.current_thread())
            resume.set();thread.join(5);self.assertFalse(thread.is_alive())
            self.assertEqual(results,['bounded refusal',self.f.ids['earth']])
            with self.server.selection_mesh_node(time.monotonic()+tcp.MAX_LOCAL_LOCK_WAIT_SECONDS):pass
            self.server.finish_selection()
        finally:
            resume.set();thread.join(5)
            if self.server.selection_owner is threading.current_thread():self.server.finish_selection()
            self.server.release_outbound(thread)
        self.assertNotIn(thread,self.server.tcp_mesh_waiters)

    def test_closed_inbound_attempt_leaves_no_future_ticket_or_custody(self):
        self.server.request_selection();before=(self.f.root/'earth/mesh-state.json').read_bytes()
        error=self.foreign(self.tcp_open)
        self.assertIsInstance(error,BlockingIOError)
        self.assertEqual(self.server.tcp_mesh_waiters,set());self.assertIsNone(self.server.local_mesh_owner)
        self.assertEqual((self.f.root/'earth/mesh-state.json').read_bytes(),before)
        self.server.finish_selection()

    def test_real_outgoing_and_inbound_waiters_each_receive_a_turn(self):
        # Hold a real ordinary Node while both TCP roles actually request it.
        ready=threading.Event();results=[]
        def outgoing():
            ready.wait(5)
            for _ in range(2):
                try:results.append(('out',self.tcp_open()))
                except BaseException as error:results.append(('out',error))
        owner=threading.Thread(target=outgoing);self.server.claim_outbound(owner)
        inbound=threading.Thread(target=lambda:(ready.wait(5),results.append(('in',self.tcp_open()))))
        self.server.request_selection()
        try:
            with self.server.selection_mesh_node(time.monotonic()+tcp.MAX_LOCAL_LOCK_WAIT_SECONDS):
                owner.start();inbound.start();ready.set()
                deadline=time.monotonic()+0.1
                while time.monotonic()<deadline:
                    with self.server.guard:waiting=len(self.server.tcp_mesh_waiters)
                    if waiting==2:break
                    time.sleep(0.001)
                self.assertEqual(waiting,2)
            self.server.finish_selection()
            owner.join(5);inbound.join(5)
            self.assertFalse(owner.is_alive());self.assertFalse(inbound.is_alive())
            self.assertEqual([role for role,_ in results],['out','in','out'])
            self.assertTrue(all(value==self.f.ids['earth'] for _,value in results))
        finally:
            ready.set()
            if owner.ident is not None:owner.join(5)
            if inbound.ident is not None:inbound.join(5)
            if self.server.selection_owner is threading.current_thread():self.server.finish_selection()
            self.server.release_outbound(owner)

    def test_expired_socket_never_gets_custody_and_releases_its_admission(self):
        before=(self.f.root/'earth/mesh-state.json').read_bytes()
        with self.assertRaisesRegex(ValueError,'deadline'):
            with self.server.mesh_node(time.monotonic()-1):self.fail('expired socket admitted')
        self.assertIsNone(self.server.local_mesh_owner);self.assertEqual(self.server.tcp_mesh_waiters,set())
        self.assertEqual((self.f.root/'earth/mesh-state.json').read_bytes(),before)

    def test_original_two_inbound_and_one_outgoing_waiter_capacity_refuses_extra_thread(self):
        entered=threading.Event();threads=[];results=[]
        def waiter():
            entered.wait(5)
            try:self.tcp_open()
            except (OSError,ValueError) as error:results.append(error)
        owner=threading.Thread(target=waiter);self.server.claim_outbound(owner)
        threads=[owner,*[threading.Thread(target=waiter) for _ in range(tcp.MAX_WORKERS)]]
        self.server.request_selection()
        try:
            with self.server.selection_mesh_node(time.monotonic()+tcp.MAX_LOCAL_LOCK_WAIT_SECONDS):
                for thread in threads:thread.start()
                entered.set();deadline=time.monotonic()+0.1
                while time.monotonic()<deadline:
                    with self.server.guard:count=len(self.server.tcp_mesh_waiters)
                    if count==tcp.MAX_WORKERS+1:break
                    time.sleep(0.001)
                self.assertEqual(tcp.MAX_WORKERS,2);self.assertEqual(count,3)
                error=self.foreign(self.tcp_open)
                self.assertIsInstance(error,ValueError);self.assertIn('capacity',str(error))
                self.assertEqual(len(self.server.tcp_mesh_waiters),3)
            self.server.finish_selection()
        finally:
            entered.set()
            for thread in threads:
                if thread.ident is not None:thread.join(5);self.assertFalse(thread.is_alive())
            if self.server.selection_owner is threading.current_thread():self.server.finish_selection()
            self.server.release_outbound(owner)

    def test_constructor_failure_releases_admission_without_claiming_a_verified_grant(self):
        self.server.request_selection()
        with patch.object(mesh,'Node',side_effect=ValueError('corrupt retained evidence')):
            with self.assertRaisesRegex(ValueError,'corrupt retained evidence'):
                with self.server.selection_mesh_node(time.monotonic()+tcp.MAX_LOCAL_LOCK_WAIT_SECONDS):pass
        self.assertIsNone(self.server.local_mesh_owner);self.assertIsNone(self.server.last_mesh_class)
        self.server.finish_selection();self.assertEqual(self.foreign(self.tcp_open),self.f.ids['earth'])

    def test_ordinary_validation_cpu_is_not_misrepresented_as_a_point_two_second_total(self):
        self.server.request_selection();real=mesh.Node
        def slow(*args,**kwargs):
            node=real(*args,**kwargs);time.sleep(tcp.MAX_LOCAL_LOCK_WAIT_SECONDS+0.02);return node
        with patch.object(mesh,'Node',side_effect=slow):
            with self.server.selection_mesh_node(time.monotonic()+tcp.MAX_LOCAL_LOCK_WAIT_SECONDS) as node:
                self.assertEqual(node.id,self.f.ids['earth'])
        self.server.finish_selection();self.assertIsNone(self.server.local_mesh_owner)

    def test_real_tls_custody_progresses_between_repeated_destination_selections(self):
        destination=self.f.servers['proxima'];source=self.f.servers['earth']
        with self.f.node('earth') as node:ident=node.enqueue(self.f.frame(),self.f.ids['proxima'])
        destination.request_selection()
        with destination.selection_mesh_node(time.monotonic()+tcp.MAX_LOCAL_LOCK_WAIT_SECONDS):pass
        destination.finish_selection();destination.request_selection()
        try:
            result=source.tick();self.assertEqual(result['errors'],[])
            with self.f.node('earth') as node:
                self.assertIn(ident,node.receipts());mesh.receipt_matches(node.receipts()[ident],node.transit(ident))
            with self.f.node('proxima') as node:self.assertIn(ident,node.receipts())
        finally:destination.finish_selection()


if __name__=='__main__':unittest.main()
