"""Actual pinned TLS custody while ordinary Native work is blocked.

All fixtures are fresh and have no value. Component fault barriers grant no
ledger/signing rights and are separate from the ordinary full-cycle campaign.
"""
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_tcp as tcp
import interstellar_transfer as wire
from regional_carriage_worker import Worker
from regional_bft_network_campaign import Campaign
from regional_contact_campaign import public
from regional_contact_node import Native,Service
from test_interstellar_tcp import Fixture

BINARY=Path(os.environ.get('RLD_CONTACT_BINARY',str(Path(__file__).parent/'regional-ledger/target/debug/rld-regional-ledger-candidate'))).resolve()


def wait(check,seconds=10):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if check():return
        time.sleep(0.025)
    raise AssertionError('bounded component observation failed')


class CarriageWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='rld-carriage-worker-')
        self.fixture=Fixture(self.temp.name,names=('earth','proxima'))
        self.worker=None

    def tearDown(self):
        if self.worker:self.worker.close()
        self.fixture.close();self.temp.cleanup()

    def enqueue(self):
        with self.fixture.node('earth') as node:
            return node.enqueue(self.fixture.frame(),self.fixture.ids['proxima'])

    def receipt(self,ident):
        try:
            with self.fixture.node('proxima') as node:return ident in node.receipts()
        except BlockingIOError:return False

    def test_real_pinned_tls_custody_and_snapshot_isolation(self):
        ident=self.enqueue();server=self.fixture.servers['earth'];self.worker=Worker(server,0.1)
        wait(lambda:self.receipt(ident))
        wait(lambda:self.worker.snapshot()['worker']['completed_passes']>0)
        snapshot=self.worker.snapshot();snapshot['worker']['completed_passes']=-1;snapshot['contacts'].clear()
        fresh=self.worker.snapshot()
        self.assertGreater(fresh['worker']['completed_passes'],0)
        self.assertIn('observations',fresh['contacts'])
        self.assertTrue(fresh['encrypted']);self.assertFalse(fresh['fallback_to_plaintext'])
        self.assertFalse(fresh['ledger_acceptance_from_transport'])

    def test_exactly_one_outgoing_owner_without_foreground_fallback(self):
        server=self.fixture.servers['earth'];self.worker=Worker(server,0.1)
        with self.assertRaisesRegex(ValueError,'belongs to its worker'):server.tick()
        with self.assertRaisesRegex(ValueError,'already owned'):Worker(server,0.1)
        self.worker.close()
        self.assertIsNone(server.outbound_owner)

    def test_close_keeps_owner_until_local_work_finishes(self):
        server=self.fixture.servers['earth'];entered=threading.Event();release=threading.Event()
        original=server._outbound_tick
        def blocked():
            entered.set();release.wait(10);return original()
        with patch.object(server,'_outbound_tick',side_effect=blocked):
            self.worker=Worker(server,0.1);self.assertTrue(entered.wait(3))
            closing=threading.Thread(target=self.worker.close);closing.start()
            try:
                wait(lambda:self.worker.stop.is_set(),3)
                self.assertTrue(closing.is_alive());self.assertFalse(self.worker.closed)
                self.assertIs(server.outbound_owner,self.worker.thread)
                with self.assertRaisesRegex(ValueError,'belongs to its worker'):server.tick()
            finally:release.set();closing.join(10)
            self.assertFalse(closing.is_alive());self.assertTrue(self.worker.closed)

    def test_failed_worker_refuses_status_and_retains_pending_evidence(self):
        ident=self.enqueue();server=self.fixture.servers['earth']
        with patch.object(server,'_outbound_tick',side_effect=RuntimeError('injected worker failure')):
            self.worker=Worker(server,0.1);wait(lambda:not self.worker.thread.is_alive())
            with self.assertRaisesRegex(ValueError,'worker failed'):self.worker.snapshot()
        with self.fixture.node('earth') as node:
            self.assertIn(ident,node.state['messages']);self.assertNotIn(ident,node.receipts())

    def test_diagnostic_capacity_failure_never_discards_evidence(self):
        ident=self.enqueue();server=self.fixture.servers['earth']
        with patch.object(server,'_outbound_tick',return_value=dict(oversized='x'*(64*1024))):
            self.worker=Worker(server,0.1);wait(lambda:not self.worker.thread.is_alive())
            with self.assertRaisesRegex(ValueError,'diagnostic capacity'):self.worker.snapshot()
        with self.fixture.node('earth') as node:self.assertIn(ident,node.state['messages'])

    def test_bad_tls_pin_keeps_pending_without_plaintext_fallback(self):
        ident=self.enqueue();server=self.fixture.servers['earth']
        server.peers[self.fixture.ids['proxima']]['tls_cert_sha256']='0'*64
        self.worker=Worker(server,0.1)
        wait(lambda:self.worker.snapshot()['worker']['completed_passes']>0)
        self.assertTrue(any('pin mismatch' in error for error in self.worker.snapshot()['errors']))
        self.assertFalse(self.receipt(ident))
        with self.fixture.node('earth') as node:
            self.assertIn(ident,node.state['messages']);self.assertNotIn(ident,node.receipts())


class NativeCarriageTests(unittest.TestCase):
    def test_actual_native_commit_moves_while_ordinary_native_observation_waits(self):
        with tempfile.TemporaryDirectory(prefix='rld-native-independent-carriage-') as temporary:
            campaign=Campaign(BINARY,Path(temporary).resolve()/'fixture')
            service=None;receiver=None;ordinary=None
            outgoing_release=threading.Event();native_entered=threading.Event();native_release=threading.Event()
            failures=[];results=[];original=tcp.Server._outbound_tick
            source=campaign.root/'mesh-1'
            def deferred(server):
                if Path(server.config['state'])==source:outgoing_release.wait(15)
                return original(server)
            try:
              with patch.object(tcp.Server,'_outbound_tick',deferred):
                receiver=tcp.Server(mesh.load(campaign.root/'mesh-config-2.json',65536),('127.0.0.1',campaign.ports[2]))
                native=Native(BINARY,campaign.node('earth',1),public(1),campaign.currency)
                service=Service(native,mesh.load(campaign.root/'mesh-config-1.json',65536),None,
                                listen=('127.0.0.1',campaign.ports[1]),bft_config=campaign.root/'bft-config-1.json')
                self.assertIsNotNone(service.carriage)
                runtime=service.bft
                candidate=campaign.cli('earth',1,'bft-candidate','--miner',public(10),'--commands',campaign.file('commands',[]))
                proposal=campaign.sign('earth',0,{'Propose':dict(round=0,snapshot=candidate,timeout=None)})['message']['Proposal']
                votes=[campaign.sign('earth',n,{'Prepare':proposal})['message'] for n in (0,2,3)]
                for message in [{'Proposal':proposal},*votes]:runtime.retain(runtime.envelope({'Signed':message}),sync=False)
                runtime.tick()
                # Two local votes have six recipient pairs; preserve the
                # ordinary four-item enqueue budget and queue the remainder
                # before testing independent carriage of already queued bytes.
                runtime.broadcast()
                commits=[i for i,body,_,local in runtime.state['messages'].bodies()
                         if local and body.get('Signed',{}).get('Vote',{}).get('phase')=='Commit']
                self.assertEqual(len(commits),1);content=runtime.state['messages'].content(commits[0])
                with mesh.Node(service.config) as node:
                    self.assertTrue(any(t['export_id']==content and t['destination']==campaign.node_ids[2]
                                        for t in node.summaries().values()))
                call=native.call
                def blocked(action,*args):
                    if action=='contact-status':native_entered.set();native_release.wait(15)
                    return call(action,*args)
                def run_tick():
                    try:results.append(service.tick())
                    except BaseException as error:failures.append(error)
                with patch.object(native,'call',side_effect=blocked):
                    ordinary=threading.Thread(target=run_tick);ordinary.start()
                    self.assertTrue(native_entered.wait(3));outgoing_release.set()
                    def received():
                        try:
                            with mesh.Node(receiver.config) as node:
                                return any(t['export_id']==content and i in node.receipts()
                                           for i,t in node.summaries().items())
                        except BlockingIOError:return False
                    try:wait(received)
                    except AssertionError as error:
                        raise AssertionError(str(error)+' worker='+str(service.carriage.snapshot())) from error
                    self.assertTrue(ordinary.is_alive())
                    self.assertFalse(native_release.is_set())
                    destination=Native(BINARY,campaign.node('earth',2),public(1),campaign.currency)
                    self.assertEqual(destination.call('status')['height'],0)
                    native_release.set();ordinary.join(15)
                self.assertFalse(ordinary.is_alive());self.assertEqual(failures,[])
                self.assertTrue(results[0]['native_observation_available'])
                self.assertEqual(runtime.signer_status()['records'],2)
                self.assertIsNone(runtime.head['pending']);self.assertIsNone(runtime.head['outbox'])
                self.assertEqual(native.call('status')['height'],0)
            finally:
                outgoing_release.set();native_release.set()
                if ordinary:ordinary.join(15)
                if service:service.close()
                if receiver:receiver.close()
                campaign.cleanup()


if __name__=='__main__':unittest.main()
