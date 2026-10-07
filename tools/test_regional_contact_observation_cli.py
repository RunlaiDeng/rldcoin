"""Fresh actual Native read projections; no Runtime, Mesh Node or sockets.

Set RLD_CONTACT_BINARY to the reviewed CLI beside its same-source helper.
All generated no-value custody, including injected refusal state, is retained.
This finite check cannot qualify consensus liveness, full fault or adoption.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

from regional_contact_campaign import Campaign
from regional_contact_node import Native, Service
from regional_paged_fault_prepare import Preparation
from regional_paged_fault_scope import inventory


class ContactObservationCliTests(unittest.TestCase):
    def test_classic_paged_complete_projections_bytes_and_refusals(self):
        project=Path(__file__).resolve().parents[1]
        binary_value=os.environ.get('RLD_CONTACT_BINARY')
        if not binary_value:self.skipTest('reviewed actual CLI required')
        binary=Path(binary_value).resolve()
        self.assertTrue(binary.is_file())
        parent=os.environ.get('RLD_CONTACT_OBSERVATION_FIXTURE')
        if parent:
            root=Path(parent).absolute();self.assertFalse(root.exists())
            root.mkdir(mode=0o700)
        else:
            root=Path(tempfile.mkdtemp(prefix='rld-contact-observation-',dir=project/'tmp'))
        deadline=time.monotonic()+60
        source=os.environ['RLD_CONTACT_OBSERVATION_IMPLEMENTATION']
        paged=Preparation(project,root/'paged',binary,source,
                          hashlib.sha256(binary.read_bytes()).hexdigest(),deadline)
        classic=Campaign(binary,root/'classic')
        self.addCleanup(classic.cleanup)
        results=[]

        def read(ledger,authority,currency,command,success=True):
            remaining=deadline-time.monotonic();self.assertGreater(remaining,0)
            start=time.monotonic()
            output=subprocess.run([str(binary),'--dir',str(ledger),'--authority',authority,
                '--currency',currency,command],cwd=project,capture_output=True,timeout=remaining)
            self.assertEqual(output.returncode,0 if success else 1,output.stderr.decode(errors='replace'))
            self.assertLessEqual(len(output.stdout),8*1024**2)
            if not success:
                self.assertEqual(output.stdout,b'')
                return output.stderr.decode(errors='replace')
            return json.loads(output.stdout),time.monotonic()-start

        def pair(profile,ledger,authority,currency):
            before=inventory(root)
            value,combined_seconds=read(ledger,authority,currency,'contact-observation')
            status,status_seconds=read(ledger,authority,currency,'contact-status')
            outgoing,outgoing_seconds=read(ledger,authority,currency,'contact-outgoing')
            self.assertEqual(set(value),{'format','currency','region','status','outgoing',
                                       'ledger_changed','signing_authority'})
            self.assertEqual(value['format'],'RLD-NATIVE-CONTACT-OBSERVATION-V1')
            self.assertEqual(value['currency'],currency)
            self.assertEqual(value['status'],status)
            self.assertEqual(value['outgoing'],outgoing)
            self.assertIs(value['ledger_changed'],False)
            self.assertIs(value['signing_authority'],False)
            native=Native(binary,ledger,authority,currency)
            service=Service.__new__(Service);service.native=native;service.region=value['region']
            self.assertEqual(service.contact_observation(),(status,outgoing))
            self.assertEqual(inventory(root),before)
            with (ledger/'LOCK').open('r+b') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                try:diagnostic=read(ledger,authority,currency,'contact-observation',False)
                finally:fcntl.flock(lock,fcntl.LOCK_UN)
            self.assertIn('lock acquisition failed because the operation would block',diagnostic)
            self.assertEqual(inventory(root),before)
            wrong=read(ledger,authority,'0'*64,'contact-observation',False)
            self.assertTrue(wrong.strip())
            self.assertEqual(inventory(root),before)
            results.append(dict(profile=profile,contacts=len(status['contacts']),offers=len(outgoing['offers']),
                combined_seconds=combined_seconds,original_pair_seconds=status_seconds+outgoing_seconds,
                projections_equal=True,private_bytes_unchanged=True,actual_lock_and_currency_refusal=True))

        pair('classic',classic.root/'earth',classic.authority,classic.currency)
        for label in ('earth','proxima'):paged.region(label)
        for _ in range(3):paged.certify('earth',[])
        signed=paged.sign_preparation('proxima')
        paged.import_preparation('proxima',signed)
        pair('paged-source',paged.regions['earth'][0]['ledger'],paged.authority,paged.pin)
        pair('paged-recipient',paged.regions['proxima'][0]['ledger'],paged.authority,paged.pin)
        self.assertGreater(results[1]['offers'],0)
        self.assertGreater(results[2]['contacts'],0)
        # Intentionally refuse new unhealthy stores once. Do not clear guards,
        # recover requests, restore bytes or reopen their Native custody later.
        for ledger,authority,currency in (
                (classic.root/'proxima',classic.authority,classic.currency),
                (paged.regions['proxima'][1]['ledger'],paged.authority,paged.pin)):
            guard=ledger/'INCIDENT_GUARD'
            self.assertEqual(guard.read_bytes(),bytes(32))
            guard.write_bytes(bytes([1])*32)
            before=inventory(root)
            refusal=read(ledger,authority,currency,'contact-observation',False)
            self.assertTrue(refusal.strip())
            self.assertEqual(inventory(root),before)
        self.assertLess(time.monotonic(),deadline)
        self.result=dict(completed=True,fixture_only=True,live_rld=False,
            results=results,complete_native_replay=True,read_only_bytes_unchanged=True,
            unhealthy_guard_refused_without_recovery=True,root=str(root),
            Runtime_Node_socket_calls=0,actual_preparation_signatures=True,
            all_old_failed_fixtures_unopened=True,full600_qualified=False)
        print('contact-observation-cli-result '+json.dumps(self.result),flush=True)


if __name__=='__main__':unittest.main()
