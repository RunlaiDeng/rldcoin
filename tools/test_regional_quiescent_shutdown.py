"""Lifecycle/deadline models only; modeled Native results grant no authority."""
import copy
import os
from pathlib import Path
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from regional_bft_node import Runtime,ORIGIN_RUNTIME_FORMAT,FORMAT
from regional_contact_node import Native,Service
from regional_native_deadline import DeadlineNative,MAX_QUIESCENCE_SECONDS


class ShutdownTests(unittest.TestCase):
    def runtime(self,kind='unsigned'):
        r=object.__new__(Runtime);r.format=ORIGIN_RUNTIME_FORMAT;r.joint=None;r.failed=False
        r._retained_native_authenticated=r._signed_query_ready=True
        directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup)
        r.root=Path(directory.name).resolve()
        r.head=dict(head='a'*64,pending={'Timeout':{'model_only':True}},outbox=None)
        r.signer=Path('/model-signer');events=[]
        def call(*args,deadline=None):
            self.assertIsNotNone(deadline);events.append(args)
            self.assertEqual(args[0],'bft-client-reconcile');self.assertNotIn('--key-file',args)
            if kind=='unknown':raise OSError('model signer head unavailable')
            if kind=='changed':raise ValueError('model different native head refuses')
            return dict(r.head, pending=None, head='b'*64 if kind in ('response','retention-failure') else 'a'*64,
                        outbox={'Timeout':{'model_response':True}} if kind in ('response','retention-failure') else None)
        r.native=SimpleNamespace(call=call);r.signing_binding={};r.caller_args=lambda: ()
        def save(value):
            if kind=='write-failure':raise OSError('model caller write refused')
            r.head=copy.deepcopy(value)
        r.save_head=save
        def retain(body):
            self.assertIsNone(r.head['pending']);self.assertIsNotNone(r.head['outbox'])
            events.append(('full-retain-model',body))
            if kind=='retention-failure':raise OSError('model complete retention refused')
        r.retain_local_body=retain
        return r,events

    def test_unsigned_and_exact_response_recovery_never_first_sign_or_tick(self):
        for kind in ('unsigned','response'):
            r,events=self.runtime(kind);native=r.native
            r.sign=r.tick=lambda *a:self.fail('quiescence attempted first-sign or a consensus unit')
            self.assertTrue(r.quiesce(time.monotonic()+MAX_QUIESCENCE_SECONDS))
            self.assertIs(r.native,native);self.assertIsNone(r.head['pending']);self.assertIsNone(r.head['outbox'])
            self.assertEqual(r.head['head'],'b'*64 if kind=='response' else 'a'*64)
            if kind=='response':self.assertEqual(events[-1][0],'full-retain-model')

    def test_unknown_changed_and_publication_failure_keep_pending(self):
        for kind in ('unknown','changed','write-failure'):
            r,events=self.runtime(kind);native=r.native;before=copy.deepcopy(r.head)
            with self.assertRaises((OSError,ValueError)):r.quiesce(time.monotonic()+MAX_QUIESCENCE_SECONDS)
            self.assertEqual(r.head,before);self.assertIs(r.native,native)

    def test_recovered_response_retention_failure_keeps_new_head_and_exact_outbox(self):
        r,events=self.runtime('retention-failure');native=r.native
        with self.assertRaisesRegex(OSError,'complete retention refused'):r.quiesce(time.monotonic()+2)
        self.assertEqual(r.head['head'],'b'*64);self.assertIsNone(r.head['pending'])
        self.assertEqual(r.head['outbox'],{'Timeout':{'model_response':True}});self.assertIs(r.native,native)

    def test_expiry_incomplete_startup_and_legacy_never_first_sign(self):
        r,events=self.runtime();before=copy.deepcopy(r.head)
        with self.assertRaises(subprocess.TimeoutExpired):r.quiesce(time.monotonic()-1)
        self.assertEqual(r.head,before);self.assertEqual(events,[])
        for attr in ('failed','_signed_query_ready','_retained_native_authenticated'):
            r,events=self.runtime();setattr(r,attr,attr=='failed')
            with self.assertRaises(ValueError):r.quiesce(time.monotonic()+2)
            self.assertEqual(events,[])
        for kind in ('legacy','joint','empty'):
            r,events=self.runtime()
            if kind=='legacy':r.format=FORMAT
            elif kind=='joint':r.joint=object()
            else:r.head['pending']=None
            self.assertFalse(r.quiesce(time.monotonic()+2));self.assertEqual(events,[])

    def service(self,recovery_failure=False):
        s=object.__new__(Service);events=[]
        s.carriage=SimpleNamespace(close=lambda:events.append('outgoing-stopped'))
        s.tcp=SimpleNamespace(close=lambda:events.append('all-incoming-stopped'))
        def recover(deadline):
            self.assertIsNone(s.carriage);self.assertIsNone(s.tcp)
            self.assertGreater(deadline,time.monotonic());events.append('recover-only')
            if recovery_failure:raise OSError('quiescence refused')
        s.bft=SimpleNamespace(quiesce=recover,close=lambda:events.append('runtime-lock-released'))
        s.trace_publisher=SimpleNamespace(close=lambda:events.append('publisher-closed'))
        fd,path=tempfile.mkstemp();os.unlink(path);s.lock=fd
        return s,events,fd

    def test_original_default_close_never_recovers_and_explicit_stop_orders_owners(self):
        for selected in (False,True):
            s,events,fd=self.service();s.close(recover_only=selected)
            expected=['outgoing-stopped','all-incoming-stopped']+(['recover-only'] if selected else [])+['runtime-lock-released','publisher-closed']
            self.assertEqual(events,expected);self.assertIsNone(s.lock)
            with self.assertRaises(OSError):os.fstat(fd)

    def test_recovery_refusal_preserves_failure_and_releases_service_resources(self):
        s,events,fd=self.service(True)
        with self.assertRaisesRegex(OSError,'quiescence refused'):s.close(recover_only=True)
        self.assertEqual(events,['outgoing-stopped','all-incoming-stopped','recover-only','runtime-lock-released','publisher-closed'])
        self.assertIsNone(s.bft);self.assertIsNone(s.lock)
        with self.assertRaises(OSError):os.fstat(fd)


class NativeDeadlineTests(unittest.TestCase):
    def test_deadline_is_shared_expired_calls_never_spawn_and_default_stays_original(self):
        native=object.__new__(Native);native.binary=Path('/model-binary');native.ledger=Path('/model-ledger');native.authority='a'*64;native.currency='b'*64
        def run(*args,**kwargs):
            kwargs['stdout'].write(b'{}');return SimpleNamespace(returncode=0)
        with patch('regional_contact_node.subprocess.run',side_effect=run) as spawned:
            native.call('model');self.assertEqual(spawned.call_args.kwargs['timeout'],30)
            native.call('model',deadline=time.monotonic()+1)
            self.assertGreater(spawned.call_args.kwargs['timeout'],0);self.assertLessEqual(spawned.call_args.kwargs['timeout'],1)
            count=spawned.call_count
            with self.assertRaises(subprocess.TimeoutExpired):native.call('model',deadline=time.monotonic()-1)
            self.assertEqual(spawned.call_count,count)
            for bad in (True,float('nan'),float('inf')):
                with self.assertRaises(ValueError):native.call('model',deadline=bad)
            self.assertEqual(spawned.call_count,count)
        seen=[];d=time.monotonic()+2
        wrapped=DeadlineNative(SimpleNamespace(call=lambda *a,**k:seen.append(k['deadline'])),d)
        wrapped.call('first');wrapped.call('second');self.assertEqual(seen,[d,d])


if __name__=='__main__':unittest.main()
