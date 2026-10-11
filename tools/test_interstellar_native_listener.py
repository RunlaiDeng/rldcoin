"""Actual native listener ownership, with fresh no-value transport directories."""
import socket
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import interstellar_tls as native
import interstellar_crypto as crypto

class NativeListenerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='rld-native-listener-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        self.context=native.Context(self.root,'a'*64,'b'*64);self.addCleanup(self.context.close)
        self.listeners=[];self.addCleanup(self.close_all)
        self.before=dict(crypto.backend().call({'Tls':'Usage'}))
    def close_all(self):
        for listener in self.listeners:listener.close()
        self.assertEqual(crypto.backend().call({'Tls':'Usage'}),self.before)
    def listener(self,callback):
        listener=native.Listener(self.context,('127.0.0.1',0),callback);self.listeners.append(listener);return listener
    def await_condition(self,condition):
        deadline=time.monotonic()+2
        while not condition() and time.monotonic()<deadline:time.sleep(.005)
        self.assertTrue(condition())
    def test_native_two_workers_refuse_third_and_close_interrupts_handshakes(self):
        reserved=set();workers=[];failures=[];refused=[]
        def callback(event,handle,deadline):
            if event==0:return 0
            if event==1:reserved.add(handle);return 1
            if event==3:refused.append(True);return 1
            if event==4:reserved.discard(handle);return 1
            if event==2:
                workers.append(threading.current_thread().name)
                try:native.Connection(self.context.provider,handle,deadline=deadline).do_handshake()
                except OSError:failures.append(True)
                return 1
            return -1
        listener=self.listener(callback)
        clients=[socket.create_connection(listener.address) for _ in range(2)]
        try:
            for client in clients:client.sendall(b'\x16')
            self.await_condition(lambda:listener.status()['active']==2)
            with socket.create_connection(listener.address,timeout=2) as rejected:self.assertEqual(rejected.recv(1),b'')
            self.await_condition(lambda:len(refused)==1)
            start=time.monotonic();listener.close()
            self.assertLess(time.monotonic()-start,1)
            self.assertEqual(len(failures),2);self.assertEqual(reserved,set());self.assertFalse(listener.is_alive())
            self.assertTrue(all(name.startswith('Dummy-') for name in workers))
        finally:
            for client in clients:client.close()

    def test_close_waits_for_callback_after_interrupt_before_releasing_custody(self):
        interrupted=threading.Event();release=threading.Event();closed=threading.Event();errors=[]
        def callback(event,handle,deadline):
            if event==0:return 0
            if event in (1,3,4):return 1
            try:native.Connection(self.context.provider,handle,deadline=deadline).do_handshake()
            except OSError:interrupted.set()
            if not release.wait(2):return -1
            return 1
        listener=self.listener(callback);client=socket.create_connection(listener.address)
        self.await_condition(lambda:listener.status()['active']==1)
        def close():
            try:listener.close();closed.set()
            except BaseException as error:errors.append(error)
        closer=threading.Thread(target=close);closer.start()
        try:
            self.assertTrue(interrupted.wait(1));self.assertFalse(closed.is_set())
        finally:release.set();closer.join(3);client.close()
        self.assertFalse(closer.is_alive());self.assertEqual(errors,[]);self.assertTrue(closed.is_set())

    def test_external_deferred_slots_share_original_capacity(self):
        calls=[]
        def callback(event,handle,deadline):
            calls.append(event)
            if event==0:return 2
            if event==1:return 0
            return 1
        listener=self.listener(callback)
        with socket.create_connection(listener.address,timeout=2) as client:self.assertEqual(client.recv(1),b'')
        self.assertNotIn(2,calls);self.assertEqual(listener.status()['accepted'],0)
        self.assertEqual(listener.status()['refused'],1)

    def test_start_response_loss_known_handle_still_joins_and_releases_callback(self):
        provider=self.context.provider;original=provider.invoke;before=len(native._callback_custody)
        def lost(operation,request,*arguments):
            result=original(operation,request,*arguments)
            if arguments:raise ValueError('MODEL_LOST_START_RESPONSE')
            return result
        with patch.object(provider,'invoke',side_effect=lost):
            with self.assertRaisesRegex(ValueError,'MODEL_LOST_START_RESPONSE'):
                native.Listener(self.context,('127.0.0.1',0),lambda event,handle,deadline:0 if event==0 else 1)
        self.assertEqual(len(native._callback_custody),before)

    def test_unproven_close_retains_executable_callback_until_proven_join(self):
        listener=self.listener(lambda event,handle,deadline:0 if event==0 else 1)
        original=listener.provider.call
        def lost(request):
            result=original(request)
            if type(request) is dict and 'ListenerClose' in request.get('Tls',{}):raise ValueError('MODEL_LOST_CLOSE_RESPONSE')
            return result
        with patch.object(listener.provider,'call',side_effect=lost):
            with self.assertRaisesRegex(ValueError,'MODEL_LOST_CLOSE_RESPONSE'):listener.close()
        self.assertIn(listener.token,native._callback_custody);self.assertIsNotNone(listener.callback)
        listener.close();self.assertNotIn(listener.token,native._callback_custody)

    def test_default_server_uses_no_python_listener_socket_or_connection_threads(self):
        from test_interstellar_tcp import Fixture
        fixture=Fixture(self.root/'mesh');self.addCleanup(fixture.close);fixture.stop('proxima')
        original=threading.Thread;created=[]
        def allowed(*args,**kwargs):
            created.append(kwargs.get('name'))
            if kwargs.get('name')!='rld-tcp-deferred-input':raise AssertionError('Python connection/listener task')
            return original(*args,**kwargs)
        with patch('interstellar_tcp.socket.socket',side_effect=AssertionError('Python listener socket')),patch.object(threading,'Thread',side_effect=allowed):fixture.start('proxima')
        self.assertEqual(created,['rld-tcp-deferred-input'])
        self.assertIsInstance(fixture.servers['proxima'].native_listener,native.Listener)
        fixture.rounds(2)

    def test_unknown_join_preserves_actual_service_descriptor_and_runtime_owner(self):
        from test_interstellar_tcp import Fixture
        from regional_contact_node import Service
        fixture=Fixture(self.root/'unknown-join');self.addCleanup(fixture.close)
        server=fixture.servers['proxima'];listener=server.native_listener
        service=Service.__new__(Service);service.carriage=None;service.tcp=server
        service.trace_publisher=None;service.lock=os.open(self.root/'service-lease',os.O_CREAT|os.O_RDWR,0o600)
        calls=[]
        class Runtime:
            def close(self):calls.append('runtime_closed')
        service.bft=Runtime();original=listener.provider.call
        def lost(request):
            result=original(request)
            if type(request) is dict and 'ListenerClose' in request.get('Tls',{}):raise ValueError('MODEL_LOST_JOIN_PROOF')
            return result
        with patch.object(listener.provider,'call',side_effect=lost):
            with self.assertRaisesRegex(ValueError,'MODEL_LOST_JOIN_PROOF'):service.close()
        self.assertIs(service.tcp,server);self.assertFalse(server.shutdown_proven)
        self.assertEqual(calls,[]);os.fstat(service.lock)
        self.assertIn(listener.token,native._callback_custody)
        service.close();self.assertIsNone(service.lock);self.assertEqual(calls,['runtime_closed'])

    def test_callback_failure_still_joins_before_error_and_self_join_refuses(self):
        def damaged(event,handle,deadline):
            if event==0:raise ValueError('MODEL_CALLBACK_FAILURE')
            return 1
        listener=self.listener(damaged)
        self.await_condition(lambda:listener.status()['failed'])
        with self.assertRaisesRegex(ValueError,'callback/task failed'):listener.close()
        self.assertTrue(listener.closed);self.assertNotIn(listener.token,native._callback_custody)
        refused=[];current=[]
        def callback(event,handle,deadline):
            if event==0:return 0
            if event==2:
                try:current[0].close()
                except ValueError as error:refused.append(str(error))
            return 1
        listener=self.listener(callback);current.append(listener)
        with socket.create_connection(listener.address,timeout=2) as client:client.recv(1)
        self.await_condition(lambda:bool(refused))
        self.assertIn('own callback thread',refused[0]);self.assertFalse(listener.closed)

if __name__=='__main__':unittest.main()
