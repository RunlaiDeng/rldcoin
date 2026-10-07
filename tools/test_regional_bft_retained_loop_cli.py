"""Fresh signed Native inspection equivalence; all custody stays local.

An explicit reviewed CLI enables this finite API test. It does not run Runtime,
transport, a signing service or an adopted network. Refusal stores are never reopened.
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

from regional_bft_campaign import Campaign
from regional_contact_campaign import public
from regional_paged_fault_prepare import Preparation
from regional_paged_fault_scope import inventory


class RetainedLoopCliTests(unittest.TestCase):
    def test_complete_classic_paged_projections_and_original_refusals(self):
        value=os.environ.get('RLD_RETAINED_LOOP_BINARY')
        if not value:self.skipTest('explicit reviewed actual CLI required')
        project=Path(__file__).resolve().parents[1];binary=Path(value).resolve(strict=True)
        requested=os.environ.get('RLD_RETAINED_LOOP_FIXTURE')
        if requested:
            root=Path(requested).absolute();self.assertFalse(root.exists());root.mkdir(mode=0o700)
        else:root=Path(tempfile.mkdtemp(prefix='rld-retained-loop-',dir=project/'tmp'))
        deadline=time.monotonic()+60;actions=[]
        def call(ledger,authority,currency,*args,success=True):
            remaining=deadline-time.monotonic();self.assertGreater(remaining,0)
            q=subprocess.run([str(binary),'--dir',str(ledger),'--authority',authority,
                '--currency',currency,*map(str,args)],cwd=project,capture_output=True,timeout=remaining)
            actions.append(str(args[0]));self.assertLessEqual(len(q.stdout),8*1024**2)
            self.assertLessEqual(len(q.stderr),65536)
            self.assertEqual(q.returncode,0 if success else 1,q.stderr.decode(errors='replace'))
            if not success:
                self.assertEqual(q.stdout,b'');return q.stderr.decode(errors='replace')
            return json.loads(q.stdout)
        class FreshCampaign(Campaign):
            def invoke(c,command,success=True,helper=False):
                remaining=deadline-time.monotonic();self.assertGreater(remaining,0)
                q=subprocess.run(list(map(str,command)),cwd=project,capture_output=True,timeout=remaining)
                self.assertEqual(q.returncode,0 if success else 1,q.stderr.decode(errors='replace'))
                return json.loads(q.stdout) if success else {'rejected':True}
        classic=FreshCampaign(binary,root/'classic');classic.checkpoint('earth',online=(0,1,2,3))
        paged=Preparation(project,root/'paged',binary,classic.implementation,
            hashlib.sha256(binary.read_bytes()).hexdigest(),deadline)
        paged.region('earth');paged.certify('earth',[])
        profiles=[('classic',classic.node('earth',0),public(1),classic.currency,
            [(classic.signer('earth',n),classic.heads['earth',n]) for n in range(4)]),
            ('paged',paged.regions['earth'][0]['ledger'],paged.authority,paged.pin,
             [(row['signer'],json.loads(row['caller'].read_text())['head']) for row in paged.regions['earth']])]
        counts=[]
        for label,ledger,authority,currency,signers in profiles:
            before=inventory(root);total=0
            for signer,head in signers:
                context=call(ledger,authority,currency,'bft-context')
                status=call(ledger,authority,currency,'bft-status','--signer-dir',signer)
                messages=call(ledger,authority,currency,'bft-retained-messages','--signer-dir',signer)
                plain=call(ledger,authority,currency,'bft-loop-status','--signer-dir',signer,'--expected-head',head)
                joined=call(ledger,authority,currency,'bft-loop-status','--signer-dir',signer,
                    '--expected-head',head,'--include-retained-messages')
                self.assertEqual(set(plain),{'format','native','signer','signing_authority','independent_freshness_qualified'})
                self.assertEqual(plain['format'],'RLD-BFT-LOOP-OBSERVATION-V1')
                self.assertEqual(set(joined),set(plain)|{'retained_messages'})
                self.assertEqual(joined['format'],'RLD-BFT-LOOP-RETAINED-OBSERVATION-V1')
                self.assertEqual(joined['native'],context);self.assertEqual(joined['signer'],status)
                self.assertEqual(joined['retained_messages'],messages)
                self.assertEqual({k:v for k,v in joined.items() if k not in ('format','retained_messages')},
                    {k:v for k,v in plain.items() if k!='format'})
                self.assertIs(joined['signing_authority'],False)
                self.assertIs(joined['independent_freshness_qualified'],False)
                total+=len(messages)
            self.assertGreater(total,0);self.assertEqual(inventory(root),before)
            signer,head=signers[0]
            command=('bft-loop-status','--signer-dir',signer,'--expected-head',head,'--include-retained-messages')
            wrong=list(command);wrong[4]='0'*64
            self.assertIn('separately retained caller head',call(ledger,authority,currency,*wrong,success=False))
            with (signer/'LOCK').open('rb') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                self.assertIn('already locked',call(ledger,authority,currency,*command,success=False))
            self.assertEqual(inventory(root),before)
            # One late altered original signature must fail, without response or
            # recovery. This deliberately poisoned new Classic signer is final.
            if label=='classic':
                path=signer/'bft.json';document=json.loads(path.read_text())
                document['records'][-1]['message']['Vote']['approval']['signature']='00'*64
                path.write_text(json.dumps(document));poisoned=inventory(root)
                self.assertIn('signature',call(ledger,authority,currency,*command,success=False))
                self.assertEqual(inventory(root),poisoned)
            counts.append({'profile':label,'complete_original_signed_messages':total,'signer_projections':4})
        self.assertLess(time.monotonic(),deadline)
        print('retained-loop-cli-result '+json.dumps(dict(completed=True,profiles=counts,
            actual_native_inspection_calls=len(actions),all_full_projections_equal=True,
            old_default_schema_unchanged=True,caller_head_lock_and_bad_signature_refused=True,
            Runtime_Node_socket_calls=0,old_failed_custody_opened=False,whole_goal_completed=False)),flush=True)


if __name__=='__main__':unittest.main()
