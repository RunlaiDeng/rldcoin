"""Fresh Native observations and separately deferred carriage; no authority."""
import errno
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest

import interstellar_mesh as mesh
import interstellar_tcp as tcp
from regional_paged_fault_scope import inventory


class KeylessDeferralGuardTests(unittest.TestCase):
    def runtime(self):
        from bft_tick_fixture import Fixture
        from regional_bft_node import FORMAT
        f=Fixture();f.format=FORMAT;f.joint=None;f.key_file=None
        f._retained_native_authenticated=True
        return f

    def test_only_exact_typed_keyless_refusal_defers_without_native_or_custody_claim(self):
        f=self.runtime()
        def busy():raise tcp.MeshTurnPending(errno.EAGAIN,'local mesh turn pending; retain evidence')
        f.broadcast=busy;f._broadcast_after_observation()
        self.assertTrue(f._carriage_deferred);self.assertEqual(f.requests,[])
        f.broadcast=lambda:None;f._broadcast_after_observation();self.assertFalse(f._carriage_deferred)

    def test_key_authority_pending_uncold_wrong_profile_or_joint_never_defer(self):
        from types import SimpleNamespace
        for why in ('key','pending','outbox','head','uncold','profile','joint'):
            f=self.runtime()
            if why=='key':f.key_file=SimpleNamespace(exists=lambda:True)
            elif why=='pending':f.head['pending']={'retained':True}
            elif why=='outbox':f.head['outbox']={'retained':True}
            elif why=='head':f.head['head']=None
            elif why=='uncold':f._retained_native_authenticated=False
            elif why=='profile':f.format='other-profile'
            else:f.joint=object()
            def busy():raise tcp.MeshTurnPending(errno.EAGAIN,'local mesh turn pending; retain evidence')
            f.broadcast=busy
            with self.subTest(why=why),self.assertRaises(tcp.MeshTurnPending):f._broadcast_after_observation()
            self.assertFalse(f._carriage_deferred);self.assertEqual(f.requests,[])

    def test_signature_persistence_generic_os_and_stop_refusals_remain_fatal(self):
        for error in (ValueError('invalid complete signature'),OSError('fsync failed'),
                      BlockingIOError(errno.EAGAIN,'untyped storage lock'),
                      tcp.MeshRuntimeStopping('TCP runtime is stopping; preserve evidence')):
            f=self.runtime()
            def refuse():raise error
            f.broadcast=refuse
            with self.subTest(error=type(error).__name__),self.assertRaises(type(error)):f._broadcast_after_observation()
            self.assertFalse(f._carriage_deferred)


class NativeKeylessCarriageTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('RLD_KEYLESS_CARRIAGE_FIXTURE') and os.environ.get('RLD_CONTACT_BINARY'),
                         'requires explicitly fresh retained fixture and bound Native binary')
    def test_actual_native_loop_survives_owned_turn_deferral_without_enqueue_sign_or_state_change(self):
        from regional_bft_network_campaign import Campaign
        from regional_bft_node import Runtime
        from regional_contact_node import Native
        from regional_contact_campaign import public
        root=Path(os.environ['RLD_KEYLESS_CARRIAGE_FIXTURE']).resolve()
        self.assertFalse(root.exists());root.mkdir(mode=0o700)
        c=Campaign(Path(os.environ['RLD_CONTACT_BINARY']),root/'fixture')
        runtime=server=None;holder=None;release=threading.Event();ready=threading.Event();errors=[];commands=[]
        class Recorded(Native):
            def call(self,*args,**kw):commands.append(args[0]);return super().call(*args,**kw)
        try:
            for _ in range(2):c.checkpoint('earth',online=(0,1,2,3))
            conf=mesh.load(c.root/'bft-config-1.json',65536);caller=Path(conf['head_file'])
            value=mesh.load(caller,8192);mesh.atomic(caller,dict(value,head=c.heads['earth',1]))
            absent=c.root/'absent';absent.mkdir(mode=0o700)
            conf=dict(conf,key_file=str(absent/'missing.json'));path=c.root/'keyless-config.json';mesh.atomic(path,conf)
            native=Recorded(c.binary,c.node('earth',1),public(1),c.currency)
            transport=mesh.load(c.root/'mesh-config-1.json',65536)
            runtime=Runtime(native,transport,path);server=tcp.Server(transport,('127.0.0.1',0))
            runtime.carriage_node=server.ordinary_mesh_node
            before={str(p):inventory(p) for p in (native.ledger,Path(conf['signer_dir']),caller.parent,Path(conf['state']),Path(transport['state']))}
            def occupy():
                try:
                    with server.mesh_node(time.monotonic()+3):
                        ready.set()
                        if not release.wait(3):raise AssertionError('original holder budget exhausted')
                except BaseException as error:errors.append(error);ready.set()
            holder=threading.Thread(target=occupy);holder.start();self.assertTrue(ready.wait(1));self.assertEqual(errors,[])
            commands.clear()
            try:report=runtime.tick()
            except OSError as error:
                import json
                (root/'counter-observation.json').write_text(json.dumps(dict(
                    error_class=type(error).__name__,errno=error.errno,diagnostic=str(error),
                    native_commands=commands,fresh_native_loop_before_carriage_error=commands==['bft-loop-status'],
                    retained_native_authenticated=runtime._retained_native_authenticated,
                    retained_height=runtime.state['height'],key_absent=not runtime.key_file.exists(),
                    original_native_signer_caller_runtime_mesh_bytes_unchanged=
                        {str(p):inventory(p) for p in map(Path,before)}==before,
                    signing_authority=False,whole_goal_completed=False),indent=2)+'\n')
                raise
            self.assertEqual(commands,['bft-loop-status'])
            self.assertEqual(report['height'],2);self.assertIs(report['autonomous_signing_enabled'],False)
            self.assertEqual(report['native_keyless_drain']['context']['parent_height'],2)
            self.assertEqual(report['native_keyless_drain']['caller_head'],runtime.head['head'])
            self.assertEqual(report['native_keyless_drain']['commits'],[])
            self.assertIs(report['native_keyless_drain']['signing_authority'],False)
            self.assertIs(report['carriage_deferred'],True)
            self.assertFalse(report['independent_bft_qualified'])
            self.assertEqual({str(p):inventory(p) for p in map(Path,before)},before)
            self.assertFalse(Path(conf['key_file']).exists())
        finally:
            release.set()
            if holder is not None:
                holder.join(1);self.assertFalse(holder.is_alive());self.assertEqual(errors,[])
            if server is not None:server.close()
            if runtime is not None:runtime.close()
            c.cleanup()


if __name__=='__main__':unittest.main()
