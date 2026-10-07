"""Local attempt timeouts grant no bytes, custody or consensus authorization."""
import unittest
from unittest.mock import patch

import interstellar_tcp as tcp
from regional_paged_fault_driver import observation_height
import test_interstellar_tcp_inbound_fairness as fairness


class NoIO:
    def __getattr__(self, name):
        raise AssertionError('expired attempt performed socket I/O: '+name)


class LocalDeadlineTests(unittest.TestCase):
    def test_expired_read_and_send_use_transport_timeout_without_io(self):
        for call in (lambda:tcp.read_exact(NoIO(),4,1),
                     lambda:tcp.send(NoIO(),{'bounded':'ground'},1)):
            with self.subTest(call=call),patch.object(tcp.time,'monotonic',return_value=2):
                with self.assertRaisesRegex(TimeoutError,'timed out; retain evidence'):
                    call()

    def test_deadline_after_mesh_open_releases_turn_without_yield_or_custody(self):
        fixture=fairness.InboundFairnessTests(methodName='runTest')
        server,clock=fixture.setup();closed=[]
        class SlowNode:
            def __init__(self,*args,**kwargs):clock.now=4
            def close(self):closed.append(True)
        try:
            with patch.object(tcp.mesh,'Node',SlowNode), \
                 patch.object(tcp.threading,'current_thread',return_value=server.outbound_owner):
                with self.assertRaisesRegex(TimeoutError,'timed out; retain evidence'):
                    with server._local_mesh_node(3,False):self.fail('expired lease yielded custody')
            self.assertEqual(closed,[True])
            self.assertIsNone(server.local_mesh_owner)
            self.assertNotIn(server.outbound_owner,server.tcp_mesh_waiters)
        finally:fixture.doCleanups()

    def test_successful_read_and_send_preserve_exact_bytes_and_remaining_bound(self):
        class Socket:
            def __init__(self):self.budget=[];self.output=[]
            def settimeout(self,value):self.budget.append(value)
            def recv(self,size):return b'x'*size
            def sendall(self,value):self.output.append(value)
        connection=Socket()
        with patch.object(tcp.time,'monotonic',return_value=1):
            self.assertEqual(tcp.read_exact(connection,4,3),b'xxxx')
            tcp.send(connection,{'ground':True},3)
        self.assertEqual(connection.budget,[2,2])
        self.assertEqual(connection.output,[b'\x00\x00\x00\x0f{"ground":true}'])

    def test_existing_driver_policy_is_unchanged_and_never_hides_native_refusal(self):
        value=dict(process_id=123,currency='1'*64,relay_enabled=True,rejected=[],
                   errors=['TCP local attempt timed out; retain evidence'],
                   consensus=dict(height=9),transport=dict(progress_observation_available=False))
        args=(123,'1'*64,'2'*64,dict(host='127.0.0.1',port=42000),27)
        self.assertEqual(observation_height(value,*args),9)
        for error in ('native rejected: invalid signature timed out',
                      'TCP connection challenge binding mismatch',
                      'invalid signature','BFT runtime requires restart after persistence failure'):
            with self.subTest(error=error):
                value['errors']=[error]
                with self.assertRaises(ValueError):observation_height(value,*args)
        value['errors']=[];value['rejected']=[{'reason':'invalid complete envelope'}]
        with self.assertRaises(ValueError):observation_height(value,*args)


if __name__ == '__main__':unittest.main()
