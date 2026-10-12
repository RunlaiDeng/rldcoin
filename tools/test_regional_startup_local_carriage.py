"""Signed no-value lifecycle models; modeled retain grants no Native rights."""
from pathlib import Path
from types import SimpleNamespace
import copy
import os
import tempfile
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
import regional_bft_node as bft
from regional_contact_node import Service
from test_interstellar_tcp import Fixture, NETWORK


class StartupCarriageTests(unittest.TestCase):
    def fixture(self):
        parent=Path(os.environ.get('RLD_RETAINED_GROUND_ROOT',str(Path(__file__).resolve().parents[1]/'tmp')))
        root=Path(tempfile.mkdtemp(prefix='rld-startup-local-carriage-',dir=parent)).resolve()
        fixture=Fixture(root,names=('earth','proxima'));fixture.stop('earth')
        self.addCleanup(fixture.close)
        ledger=root/'native-model';ledger.mkdir(mode=0o700)
        from interstellar_crypto import backend,FORMAT as CRYPTO_FORMAT
        profile=dict(format=CRYPTO_FORMAT,implementation=backend().implementation)
        binary=Path(os.environ['RLD_CONTACT_BINARY']).resolve()
        native=SimpleNamespace(binary=binary,currency=NETWORK,authority='b'*64,ledger=ledger,
            call=lambda *a,**k:profile if a[0]=='contact-crypto-info' else dict(currency=NETWORK,region='1'*64))
        return fixture,native

    def construct(self,failure=None,parallel=True,events=None):
        fixture,native=self.fixture();events=[] if events is None else events;packet=[]
        class ModeledRuntime:
            format=bft.ORIGIN_RUNTIME_FORMAT;joint=None
            binding={'model':'no-native-authority'}
            def __init__(self,*args):events.append('cold-caller-reconciled')
            def prime_local_carriage(self):
                events.append('prime')
                if failure:raise OSError('prime custody refused')
                with self.carriage_node() as node:
                    packet.append(node.enqueue(fixture.frame(),fixture.ids['proxima']))
                events.append('durable-carriage')
            def close(self):events.append('runtime-closed')
        class ModeledWorker:
            def __init__(self,server):
                events.append('worker-start')
                with mesh.Node(server.config) as node:
                    self.first_packets={mesh.digest(t['packet']) for t in node.prepare_exchange(fixture.ids['proxima'])['body']['transits']}
            def close(self):events.append('worker-closed')
        with patch.object(bft,'Runtime',ModeledRuntime),patch('regional_carriage_worker.Worker',ModeledWorker):
            service=Service(native,fixture.configs['earth'],None,bft_config=Path('modeled-unused'),parallel_carriage=parallel)
        self.addCleanup(service.close)
        return service,events,packet

    def test_signed_local_carriage_precedes_first_worker_preparation(self):
        service,events,packet=self.construct()
        self.assertEqual(events,['cold-caller-reconciled','prime','durable-carriage','worker-start'])
        self.assertIn(packet[0],service.carriage.first_packets)
        self.assertEqual(service.receive_after,{'novel':None,'background':None})
        self.assertEqual(service.bft_intake_pending.packets,frozenset())

    def test_failed_prime_never_starts_worker(self):
        events=[]
        with self.assertRaisesRegex(OSError,'prime custody refused'):self.construct(failure=True,events=events)
        self.assertEqual(events,['cold-caller-reconciled','prime','runtime-closed'])

    def test_nonparallel_lifecycle_keeps_original_start(self):
        service,events,packet=self.construct(parallel=False)
        self.assertEqual(events,['cold-caller-reconciled']);self.assertEqual(packet,[])
        self.assertIsNone(service.carriage)


class PrimingBoundaryTests(unittest.TestCase):
    def runtime(self):
        parent=Path(os.environ.get('RLD_RETAINED_GROUND_ROOT',str(Path(__file__).resolve().parents[1]/'tmp')))
        root=Path(tempfile.mkdtemp(prefix='rld-prime-boundary-',dir=parent)).resolve()
        queue=root/'bft-submissions';queue.mkdir(mode=0o700)
        runtime=object.__new__(bft.Runtime)
        runtime.format=bft.ORIGIN_RUNTIME_FORMAT;runtime.joint=None;runtime.failed=False
        runtime._retained_native_authenticated=True;runtime._signed_query_ready=True
        runtime.head=dict(head='a'*64,pending=None,outbox=None)
        runtime.native=SimpleNamespace(ledger=root);runtime.state={'messages':{}}
        envelope=dict(body={'Submission':[{'modeled':'no-native-authority'}]},evidence={'model':True})
        mesh.atomic(queue/'input.json',envelope);events=[]
        def retain(value,local):
            self.assertTrue(local);self.assertEqual(value,envelope)
            events.append('complete-retain-model');runtime.state['messages'][mesh.digest(value['body'])]=True
        runtime.retain=retain;runtime.broadcast=lambda:events.append('original-broadcast-model')
        return runtime,events,queue,envelope

    def test_exact_original_spool_retention_then_broadcast_and_no_duplicate_pass(self):
        runtime,events,queue,envelope=self.runtime();head=copy.deepcopy(runtime.head)
        self.assertTrue(runtime.prime_local_carriage())
        self.assertEqual(events,['complete-retain-model','original-broadcast-model'])
        self.assertFalse(runtime.prime_local_carriage());self.assertEqual(runtime.head,head)
        self.assertEqual(mesh.load(queue/'input.json',wire.MAX_PAYLOAD),envelope)

    def test_failed_or_incomplete_startup_pending_and_outbox_never_read_spool(self):
        for field,value in [('failed',True),('_retained_native_authenticated',False),('_signed_query_ready',False),('pending',{'model':True}),('outbox',{'model':True})]:
            runtime,events,_,_=self.runtime()
            if field in ('pending','outbox'):runtime.head[field]=value
            else:setattr(runtime,field,value)
            with self.assertRaises(ValueError):runtime.prime_local_carriage()
            self.assertEqual(events,[])

    def test_keyless_relay_never_calls_signing_or_tick(self):
        runtime,events,_,_=self.runtime()
        runtime.key_file=None
        def forbidden(*args,**kwargs):self.fail('startup carriage attempted signing or a consensus unit')
        runtime.sign=runtime.tick=runtime.reconcile=forbidden
        self.assertTrue(runtime.prime_local_carriage())
        self.assertEqual(events,['complete-retain-model','original-broadcast-model'])

    def test_capacity_and_symlink_refusal_precede_retention(self):
        runtime,events,queue,envelope=self.runtime()
        for i in range(32):mesh.atomic(queue/str(i),envelope)
        with self.assertRaisesRegex(ValueError,'spool capacity'):runtime.prime_local_carriage()
        self.assertEqual(events,[])
        runtime,events,queue,envelope=self.runtime()
        (queue/'link.json').symlink_to(queue/'input.json')
        with self.assertRaises(ValueError):runtime.prime_local_carriage()
        self.assertNotIn('original-broadcast-model',events)
        self.assertEqual(mesh.load(queue/'input.json',wire.MAX_PAYLOAD),envelope)

    def test_legacy_joint_and_authentication_or_publication_failure_keep_evidence(self):
        for kind in ('legacy','joint','retain','broadcast'):
            runtime,events,queue,envelope=self.runtime()
            if kind=='legacy':runtime.format=bft.FORMAT
            elif kind=='joint':runtime.joint=object()
            elif kind=='retain':runtime.retain=lambda *a,**k:(_ for _ in ()).throw(ValueError('complete Native retain refused'))
            else:runtime.broadcast=lambda:(_ for _ in ()).throw(OSError('durable carriage refused'))
            if kind in ('legacy','joint'):self.assertFalse(runtime.prime_local_carriage());self.assertEqual(events,[])
            else:
                with self.assertRaises((OSError,ValueError)):runtime.prime_local_carriage()
            self.assertEqual(mesh.load(queue/'input.json',wire.MAX_PAYLOAD),envelope)


if __name__=='__main__':unittest.main()
