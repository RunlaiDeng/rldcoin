"""Signed no-value ground transport wake; never Native or payment authority."""
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
from test_interstellar_tcp import Fixture


class IncomingCarriageWakeTests(unittest.TestCase):
    def fixture(self):
        parent=Path(os.environ.get('RLD_RETAINED_GROUND_ROOT',str(Path(__file__).resolve().parents[1]/'tmp'))).resolve()
        parent.mkdir(parents=True,exist_ok=True)
        fixture=Fixture(tempfile.mkdtemp(prefix='rld-incoming-carriage-wake-',dir=parent))
        self.addCleanup(fixture.close)
        fixture.rounds(2)  # Original discovery makes this onward destination known.
        server=fixture.servers['proxima'];notices=[]
        def notify():
            self.assertIsNone(server.local_mesh_owner)
            with fixture.node('proxima') as node:
                notices.append(set(node.state['messages']))
                self.assertFalse(node.status()['payment_authorized'])
        owner=threading.Thread(target=lambda:None)
        server.claim_outbound(owner,wake=notify)
        self.addCleanup(lambda:server.release_outbound(owner) if server.outbound_owner is owner else None)
        with fixture.node('earth') as node:
            packet=node.enqueue(fixture.frame(),fixture.ids['andromeda'])
            bundle=tcp.outgoing(node,fixture.ids['proxima'])
        return fixture,server,notices,packet,bundle

    def test_exact_new_forwarded_input_wakes_outgoing_after_close_without_receive_owner(self):
        fixture,server,notices,packet,bundle=self.fixture()
        self.assertIsNone(server.receive_wake)
        with server.mesh_node(time.monotonic()+tcp.ATTEMPT_SECONDS) as node:
            node.receive(bundle,fixture.ids['earth'])
            self.assertEqual(notices,[])
            self.assertIn(packet,node.state['messages'])
            self.assertNotIn(packet,node.receipts())
        self.assertEqual(notices,[{packet}])
        with server.mesh_node(time.monotonic()+tcp.ATTEMPT_SECONDS) as node:
            node.receive(bundle,fixture.ids['earth'])
        self.assertEqual(notices,[{packet}])
        with fixture.node('proxima') as node:self.assertIn(packet,node.state['messages'])

    def test_actual_TLS_input_notifies_once_and_keeps_forwarding_custody_distinct(self):
        fixture,server,notices,packet,bundle=self.fixture()
        report=fixture.servers['earth'].tick()
        self.assertFalse(report['errors']);self.assertEqual(notices,[{packet}])
        fixture.servers['earth'].tick();self.assertEqual(notices,[{packet}])
        with fixture.node('proxima') as node:
            self.assertIn(packet,node.state['messages']);self.assertNotIn(packet,node.receipts())

    def test_failed_write_body_close_and_signature_never_wake(self):
        for failure in ('write','body','close','signature'):
            with self.subTest(failure=failure):
                fixture,server,notices,packet,bundle=self.fixture()
                original=mesh.Node.close
                def refused_close(node):original(node);raise OSError('controlled close refusal')
                if failure=='signature':bundle['signature']='0'*128
                close_patch=patch.object(mesh.Node,'close',autospec=True,side_effect=refused_close) if failure=='close' else nullcontext()
                with self.assertRaises((OSError,ValueError)),close_patch:
                    with server.mesh_node(time.monotonic()+tcp.ATTEMPT_SECONDS) as node:
                        if failure=='write':
                            with patch.object(mesh,'atomic',side_effect=OSError('write refused')):node.receive(bundle,fixture.ids['earth'])
                        else:
                            node.receive(bundle,fixture.ids['earth'])
                            if failure=='body':raise OSError('body refused')
                self.assertEqual(notices,[]);self.assertIsNone(server.local_mesh_owner)

    def test_both_notices_keep_distinct_owners_and_failure_fallback(self):
        fixture,server,notices,packet,bundle=self.fixture();receive=[]
        def incoming():receive.append(True)
        server.claim_receive_wake(incoming)
        self.addCleanup(lambda:server.release_receive_wake(incoming))
        def refused():raise OSError('outgoing notice refused')
        server.outbound_wake=refused
        with server.mesh_node(time.monotonic()+tcp.ATTEMPT_SECONDS) as node:node.receive(bundle,fixture.ids['earth'])
        self.assertEqual(receive,[True]);self.assertEqual(server.outbound_wake_failures,1)
        with fixture.node('proxima') as node:
            self.assertIn(packet,node.state['messages']);self.assertNotIn(packet,node.receipts())
        owner=server.outbound_owner;server.release_outbound(owner)
        fixture.rounds(2)
        with fixture.node('andromeda') as node:
            self.assertIn(packet,node.receipts());self.assertFalse(node.status()['payment_authorized'])


if __name__=='__main__':unittest.main()
