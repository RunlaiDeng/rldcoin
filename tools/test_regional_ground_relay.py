"""Real sockets and pinned TLS; stream byte counts never grant payment rights."""
import socket
import tempfile
import time
import unittest

import interstellar_mesh as mesh
from regional_ground_relay import MeteredRelay
from test_interstellar_tcp import Fixture


class RelayTests(unittest.TestCase):
    def meter(self, target=('127.0.0.1',1), enabled=True):
        meter=MeteredRelay(target,'explicit_test_hop',enabled)
        self.addCleanup(meter.close)
        return meter

    def wait(self, check):
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            if check():return
            time.sleep(.01)
        self.fail('bounded meter test observation timed out')

    def test_actual_partial_send_before_error_is_retained_exactly(self):
        meter=self.meter()
        left,right=socket.socketpair()
        self.addCleanup(left.close);self.addCleanup(right.close)
        class Partial:
            calls=0
            def send(self,view):
                self.calls+=1
                if self.calls>1:raise OSError('injected partial send failure')
                return left.send(view[:3])
        meter.add(client_to_target_received=6)
        with self.assertRaises(OSError):meter.send(Partial(),b'abcdef','client_to_target',time.monotonic()+1)
        self.assertEqual(right.recv(10),b'abc')
        row=meter.report()
        self.assertEqual(row['client_to_target_sent'],3)
        self.assertEqual(row['observed_bytes_not_yet_forwarded'],3)
        self.assertFalse(row['custody_acknowledged'])

    def test_explicit_disabled_contact_refuses_actual_socket_before_target(self):
        meter=self.meter(enabled=False)
        with socket.create_connection(('127.0.0.1',meter.port),timeout=1) as client:
            self.assertEqual(client.recv(1),b'')
        self.wait(lambda:meter.report()['refused_connections']==1)
        self.assertEqual(meter.report()['ciphertext_bytes_forwarded'],0)

    def test_signed_ground_transport_frame_through_pinned_tls_is_metered_both_directions(self):
        temporary=tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        fixture=Fixture(temporary.name,names=('earth','proxima'))
        self.addCleanup(fixture.close)
        meter=self.meter(('127.0.0.1',fixture.ports['proxima']))
        fixture.stop('earth')
        fixture.configs['earth']['contacts'][0]['port']=meter.port
        fixture.start('earth')
        raw=fixture.frame(899)
        with fixture.node('earth') as node:ident=node.enqueue(raw,fixture.ids['proxima'])
        fixture.servers['earth'].tick()
        with fixture.node('proxima') as node:
            self.assertIn(ident,node.state['messages'])
            self.assertEqual(mesh.transit_check(node.state['messages'][ident],node.network)[1],raw)
            self.assertFalse(node.status()['payment_authorized'])
        self.wait(lambda:meter.report()['active_connections']==0)
        row=meter.report()
        self.assertGreater(row['client_to_target_sent'],0)
        self.assertGreater(row['target_to_client_sent'],0)
        self.assertEqual(row['client_to_target_received'],row['client_to_target_sent'])
        self.assertEqual(row['target_to_client_received'],row['target_to_client_sent'])
        self.assertFalse(row['TLS_terminated'])
        self.assertFalse(row['physical_wire_bytes_measured'])
        self.assertFalse(row['ledger_accepted'])

    def test_counter_saturation_is_unknown_and_cannot_wrap_or_grant_custody(self):
        meter=self.meter()
        with meter.lock:meter.counts['client_to_target_sent']=2**63-1
        with self.assertRaisesRegex(ValueError,'counter bound'):
            meter.add(client_to_target_sent=1)
        row=meter.report()
        self.assertFalse(row['metric_counters_available'])
        self.assertIsNone(row['ciphertext_bytes_forwarded'])
        self.assertIsNone(row['client_to_target_sent'])

    def test_nonliteral_external_and_ipv6_targets_refuse(self):
        for target in (('localhost',1),('192.0.2.1',1),('::1',1),('127.0.0.1',0)):
            with self.assertRaises(ValueError):MeteredRelay(target,'hop')

    def test_owned_threads_close_with_listener_and_workers(self):
        meter=self.meter()
        meter.close()
        self.assertFalse(meter.thread.is_alive())
        self.assertFalse(any(worker.is_alive() for worker in meter.workers))


if __name__=='__main__':unittest.main()
