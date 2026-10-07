import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import interstellar_mesh as mesh
from regional_paged_fault_driver import Driver
from regional_paged_fault_launch import Config, PHASES, SLOTS

class StoppedObservationTests(unittest.TestCase):
    def setup_model(self, root, returncode=0):
        d=Driver.__new__(Driver);d.root=root;d.phase=PHASES[0];d.currency='1'*64
        d.regions={'earth':'3'*64};d.stopped_observations={};d.unknowns=0;d.tls_observations=set()
        d.configs={(p,'earth',0):Config(p,'earth',0,True,b'{}',b'{}',('not-executed','--mesh-listen','127.0.0.1:42000')) for p in PHASES}
        d.observed={'transport_pins':[{'tls_cert_sha256':'2'*64} for _ in SLOTS]}
        old=SimpleNamespace(pid=101,returncode=returncode,poll=lambda:returncode,wait=lambda **kw:None)
        d.processes={('earth',0):old};d.logs={('earth',0):io.StringIO()};d.terminal=[]
        value=dict(process_id=101,currency=d.currency,region=d.regions['earth'],relay_enabled=True,rejected=[],errors=[],
          consensus=dict(height=12,autonomous_signing_enabled=True),
          transport=dict(tcp=dict(encrypted=True,tls_version='TLSv1.3',fallback_to_plaintext=False,
          plaintext_selected_explicitly=False,tls_cert_sha256='2'*64,listener=dict(host='127.0.0.1',port=42000),
          limits=dict(inbound_workers=2,local_attempt_seconds=3.0,local_lock_wait_seconds=.2))))
        p=root/'mesh/earth-0/regional-contact-status.json';p.parent.mkdir(parents=True);mesh.atomic(p,value)
        return d,p,value
    def restart(self,d,pid=102):
        d.phase='keyless-drain';d.processes={('earth',0):SimpleNamespace(pid=pid,poll=lambda:None)}
    def test_exact_clean_predecessor_is_unknown_until_new_publication(self):
        with tempfile.TemporaryDirectory(dir='/Users/galaxy/GitHub/rldcoin/tmp') as t:
            d,p,v=self.setup_model(Path(t));before=p.read_bytes();d.stop_all();self.restart(d)
            self.assertEqual(d.observations(),{('earth',0):None});self.assertEqual(d.unknowns,1)
            self.assertFalse(d.tls_observations);self.assertEqual(p.read_bytes(),before)
            v['process_id']=102;v['consensus']['autonomous_signing_enabled']=False;mesh.atomic(p,v)
            self.assertEqual(d.observations(),{('earth',0):12});self.assertEqual(d.tls_observations,{('earth',0)})
            p.write_bytes(before)
            with self.assertRaisesRegex(ValueError,'another process/domain'):d.observations()
    def test_reused_pid_does_not_credit_unchanged_signing_observation(self):
        with tempfile.TemporaryDirectory(dir='/Users/galaxy/GitHub/rldcoin/tmp') as t:
            d,p,v=self.setup_model(Path(t));d.stop_all();self.restart(d,101)
            self.assertEqual(d.observations(),{('earth',0):None});self.assertFalse(d.tls_observations)
            v['consensus']['autonomous_signing_enabled']=False;mesh.atomic(p,v)
            self.assertEqual(d.observations(),{('earth',0):12})
    def test_changed_old_pid_other_domain_or_slot_remains_fatal(self):
        for change in ('bytes','currency','region','slot'):
            with self.subTest(change=change),tempfile.TemporaryDirectory(dir='/Users/galaxy/GitHub/rldcoin/tmp') as t:
                d,p,v=self.setup_model(Path(t));d.stop_all();self.restart(d)
                if change=='bytes':p.write_bytes(p.read_bytes()+b'\n')
                elif change=='slot':d.stopped_observations[('earth',1)]=d.stopped_observations.pop(('earth',0))
                else:v[change]='9'*64;mesh.atomic(p,v)
                with self.assertRaises(ValueError):d.observations()
    def test_no_clean_own_stop_never_accepts_foreign_status(self):
        for reason in ('unowned','unclean','wrong-domain','invalid-TLS'):
            with self.subTest(reason=reason),tempfile.TemporaryDirectory(dir='/Users/galaxy/GitHub/rldcoin/tmp') as t:
                d,p,v=self.setup_model(Path(t),-15 if reason=='unclean' else 0)
                if reason=='wrong-domain':v['region']='9'*64;mesh.atomic(p,v)
                if reason=='invalid-TLS':v['transport']['tcp']['fallback_to_plaintext']=True;mesh.atomic(p,v)
                if reason!='unowned':
                    if reason=='unclean':
                        with self.assertRaisesRegex(ValueError,'shutdown was unclean'):d.stop_all()
                    else:d.stop_all()
                self.assertFalse(d.stopped_observations);self.restart(d)
                with self.assertRaises(ValueError):d.observations()
    def test_new_report_keeps_pid_tls_cap_errors_and_keyless_guards(self):
        for change in ('TLS','cap','fatal','signing','currency','foreign','region'):
            with self.subTest(change=change),tempfile.TemporaryDirectory(dir='/Users/galaxy/GitHub/rldcoin/tmp') as t:
                d,p,v=self.setup_model(Path(t));d.stop_all();self.restart(d)
                v['process_id']=102;v['consensus']['autonomous_signing_enabled']=False
                if change=='TLS':v['transport']['tcp']['tls_cert_sha256']='9'*64
                elif change=='cap':v['consensus']['height']=28
                elif change=='fatal':v['errors']=['[Errno 22] Invalid argument']
                elif change=='signing':v['consensus']['autonomous_signing_enabled']=True
                elif change in ('currency','region'):v[change]='9'*64
                else:v['process_id']=103
                mesh.atomic(p,v)
                with self.assertRaises(ValueError):d.observations()
    def test_dead_process_stale_and_unknown_deadline_still_fail(self):
        with tempfile.TemporaryDirectory(dir='/Users/galaxy/GitHub/rldcoin/tmp') as t:
            d,p,v=self.setup_model(Path(t));d.stop_all();self.restart(d)
            d.processes[('earth',0)].poll=lambda:1
            with self.assertRaisesRegex(ValueError,'exited prematurely'):d.observations()
            self.restart(d);d.deadline=0
            with self.assertRaisesRegex(ValueError,'budget exhausted'):d.wait('new-pid',lambda h:False)
