"""Fresh actual classic/paged pinned replay; no Runtime, Node or sockets.

Requires a reviewed CLI and its same-source helper. Every generated fixture,
including one-shot refusal custody, stays local. This is finite API evidence.
"""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_campaign import Campaign
from regional_bft_pinned_cold import FORMAT, OBSERVED_FORMAT
from regional_bft_retention import Messages, pack_state
from regional_contact_campaign import public
from regional_paged_fault_prepare import Preparation
from regional_paged_fault_scope import inventory
from verify_regional_bft_stopped_batch import (
    verify_stopped_state_pinned, verify_stopped_state_pinned_observed,
)


class ObservedColdCliTests(unittest.TestCase):
    def test_complete_classic_paged_equivalence_and_original_refusals(self):
        project=Path(__file__).resolve().parents[1]
        value=os.environ.get('RLD_OBSERVED_COLD_BINARY')
        if not value:self.skipTest('reviewed actual CLI required')
        binary=Path(value).resolve();self.assertTrue(binary.is_file())
        fixture=os.environ.get('RLD_OBSERVED_COLD_FIXTURE')
        if fixture:
            root=Path(fixture).absolute();self.assertFalse(root.exists());root.mkdir(mode=0o700)
        else:root=Path(tempfile.mkdtemp(prefix='rld-observed-cold-',dir=project/'tmp'))
        deadline=time.monotonic()+60
        actions=[]

        def call(ledger,authority,currency,*args,success=True):
            remaining=deadline-time.monotonic();self.assertGreater(remaining,0)
            result=subprocess.run([str(binary),'--dir',str(ledger),'--authority',authority,
                '--currency',currency,*map(str,args)],cwd=project,capture_output=True,timeout=remaining)
            actions.append(str(args[0]));self.assertLessEqual(len(result.stdout),8*1024**2)
            self.assertLessEqual(len(result.stderr),65536)
            self.assertEqual(result.returncode,0 if success else 1,result.stderr.decode(errors='replace'))
            if not success:
                self.assertEqual(result.stdout,b'');return result.stderr.decode(errors='replace')
            return wire.decode_json(result.stdout)

        class FreshCampaign(Campaign):
            def invoke(c,command,success=True,helper=False):
                remaining=deadline-time.monotonic();self.assertGreater(remaining,0)
                result=subprocess.run(list(map(str,command)),cwd=project,capture_output=True,timeout=remaining)
                self.assertEqual(result.returncode,0 if success else 1,result.stderr.decode(errors='replace'))
                return json.loads(result.stdout) if success else dict(rejected=True)

        classic=FreshCampaign(binary,root/'classic')
        certificate=classic.checkpoint('earth',online=(0,1,2,3))
        paged=Preparation(project,root/'paged',binary,os.environ['RLD_OBSERVED_COLD_IMPLEMENTATION'],
            hashlib.sha256(binary.read_bytes()).hexdigest(),deadline)
        paged.region('earth');paged.certify('earth',[])
        profiles=[('classic',classic.node('earth',0),public(1),classic.currency,
            classic.regions['earth'],public(2),[classic.signer('earth',n) for n in range(4)],certificate),
            ('paged',paged.regions['earth'][0]['ledger'],paged.authority,paged.pin,
             paged.region_ids[paged.origin],paged.keys[0],[row['signer'] for row in paged.regions['earth']],
             mesh.load(paged.root/'earth/preparation-certificate-1.json',8*1024**2))]
        results=[]
        for label,ledger,authority,currency,region,key,signers,certificate in profiles:
            head=call(ledger,authority,currency,'history-head')['history_head']
            proof=call(ledger,authority,currency,'proof')
            bodies=[{'Finalized':certificate}]
            for signer in signers:
                bodies.extend({'Signed':message} for message in
                    call(ledger,authority,currency,'bft-retained-messages','--signer-dir',signer))
            self.assertEqual(len(bodies),10)
            envelopes=[];messages=Messages()
            request=root/(label+'-inputs');request.mkdir(mode=0o700)
            for n,body in enumerate(bodies):
                path=request/(str(n)+'.json')
                envelope=dict(format='RLD-REGIONAL-BFT-NETWORK-V2',currency=currency,region=region,
                              evidence=proof,body=body)
                mesh.atomic(path,envelope)
                packed=call(ledger,authority,currency,'bft-network-pack','--file',path)
                mesh.atomic(path,packed)
                checked=call(ledger,authority,currency,'bft-network-check','--file',path)
                messages=messages.append(mesh.digest(body),packed,checked['value'],n%2==0)
                envelopes.append(packed)

            def plan(name,entries):
                directory=root/(label+'-'+name);directory.mkdir(mode=0o700);batches=[]
                for offset in range(0,len(entries),4):
                    raw=wire.canonical(entries[offset:offset+4]);digest=hashlib.sha256(raw).hexdigest()
                    mesh.atomic(directory/(digest+'.json'),entries[offset:offset+4])
                    batches.append(dict(sha256=digest,bytes=len(raw),envelopes=len(entries[offset:offset+4])))
                path=directory/'plan.json'
                mesh.atomic(path,dict(format=FORMAT,currency=currency,region=region,batches=batches))
                return path

            path=plan('valid-plan',envelopes);before=inventory(root)
            current=call(ledger,authority,currency,'history-check','--expected-head',head)
            original=call(ledger,authority,currency,'bft-network-check-plan','--file',path,'--expected-head',head)
            observed=call(ledger,authority,currency,'bft-network-check-plan-observed','--file',path,'--expected-head',head)
            self.assertEqual(set(observed),{'format','checked','current','ledger_changed','signing_authority'})
            self.assertEqual(observed['format'],OBSERVED_FORMAT)
            self.assertEqual(observed['checked'],original);self.assertEqual(observed['current'],current)
            self.assertIs(observed['ledger_changed'],False);self.assertIs(observed['signing_authority'],False)
            self.assertEqual(len(original['batches']),3)
            self.assertEqual(sum(len(row['results']) for row in original['batches']),10)
            self.assertEqual(inventory(root),before)

            directory=root/(label+'-retained');directory.mkdir(mode=0o700)
            config=dict(state=str(directory),format='RLD-REGIONAL-BFT-NODE-V1',key=key)
            state=dict(format=config['format'],binding=dict(currency=currency,region=region,key=key),
                height=current['height'],tip=current['tip'],messages=messages,snapshot_cache=[],cursor=0)
            mesh.atomic(directory/'state.json',pack_state(state));before=inventory(root)
            native=SimpleNamespace(currency=currency,call=lambda *args:call(ledger,authority,currency,*args))
            at=len(actions);legacy=verify_stopped_state_pinned(native,config,root,head)
            self.assertEqual(actions[at:],['history-check','bft-network-check-plan'])
            at=len(actions);answer=verify_stopped_state_pinned_observed(native,config,root,head)
            self.assertEqual(actions[at:],['bft-network-check-plan-observed'])
            self.assertEqual(answer,legacy);self.assertEqual(answer['messages_authenticated'],10)
            self.assertEqual(inventory(root),before)
            with (ledger/'LOCK').open('r+b') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                try:
                    refused=call(ledger,authority,currency,'bft-network-check-plan-observed',
                                 '--file',path,'--expected-head',head,success=False)
                finally:fcntl.flock(lock,fcntl.LOCK_UN)
            self.assertIn('lock acquisition failed because the operation would block',refused)
            for pin,domain in [('f'*64,currency),(head,'0'*64)]:
                call(ledger,authority,domain,'bft-network-check-plan-observed','--file',path,
                     '--expected-head',pin,success=False)
            self.assertEqual(inventory(root),before)
            bad=copy.deepcopy(envelopes)
            bad[-1]['body']['Signed']['Vote']['approval']['signature']='00'*64
            badpath=plan('later-invalid-signature',bad);before=inventory(root)
            call(ledger,authority,currency,'bft-network-check-plan-observed','--file',badpath,
                 '--expected-head',head,success=False)
            self.assertEqual(inventory(root),before)
            broken=plan('declared-capacity',envelopes)
            value=mesh.load(broken,8*1024**2);value['batches'][-1]['envelopes']=5;mesh.atomic(broken,value)
            before=inventory(root)
            call(ledger,authority,currency,'bft-network-check-plan-observed','--file',broken,
                 '--expected-head',head,success=False)
            self.assertEqual(inventory(root),before)
            # This alternate healthy fixture is poisoned once, queried once,
            # retained forever, and never restored or reopened afterwards.
            alternate=classic.node('earth',3) if label=='classic' else paged.regions['earth'][3]['ledger']
            guard=alternate/'INCIDENT_GUARD';self.assertEqual(guard.read_bytes(),bytes(32))
            guard.write_bytes(bytes([1])*32);before=inventory(root)
            call(alternate,authority,currency,'bft-network-check-plan-observed','--file',path,
                 '--expected-head',head,success=False)
            self.assertEqual(inventory(root),before)
            results.append(dict(profile=label,complete_envelopes=10,batches=3,
                original_history_and_plan_equal=True,stopped_original_equal=True,
                stopped_native_calls_before=2,stopped_native_calls_after=1,
                full_later_signature_refused=True,lock_head_domain_capacity_pending_refused=True,
                private_bytes_unchanged=True))
        self.assertLess(time.monotonic(),deadline)
        print('observed-cold-cli-result '+json.dumps(dict(completed=True,root=str(root),
            fixture_only=True,live_rld=False,results=results,actual_Native_and_fixture_signatures=True,
            Runtime_Node_socket_calls=0,old_failed_fixtures_unopened=True,full600_qualified=False)),flush=True)


if __name__=='__main__':unittest.main()
