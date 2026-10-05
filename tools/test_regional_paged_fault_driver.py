"""Refuse unsafe driver transitions; no Native, Runtime, sign or socket is run."""
import copy
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
from regional_paged_fault_driver import Driver, NativeReadBusy, observation_height, compatible, statement_id, retain_original_objects
from regional_paged_fault_launch import Config, PHASES, SLOTS
from regional_paged_fault_scope import REGIONS
from regional_paged_fault_prepared import Bound

PROJECT=Path('/Users/galaxy/GitHub/rldcoin')


class Relay:
    instances=[]
    def __init__(self,port,target):self.port,self.target,self.enabled=port,target,False;self.closed=False;self.instances.append(self)
    def enable(self):self.enabled=True
    def report(self):return dict(refused_connections=1,TLS_terminated=False)
    def close(self):self.closed=True


class Model(Driver):
    """Only protocol-independent sequencing. No fabricated result is qualification."""
    def __init__(self,root):
        self.root=root;self.output=root/'output';self.currency='1'*64;self.regions={r:str(i+2)*64 for i,r in enumerate(REGIONS)}
        self.configs={};self.observed=dict(transport_pins=[dict(node_id=f'{i+1:064x}') for i in range(12)])
        for phase in PHASES:
            for i,(r,n) in enumerate(SLOTS):
                contacts=[]
                if (r,n)==('earth',1):contacts=[dict(peer=self.observed['transport_pins'][5]['node_id'],port=42100)]
                if (r,n)==('proxima',1):contacts=[dict(peer=self.observed['transport_pins'][1]['node_id'],port=42101)]
                self.configs[phase,r,n]=Config(phase,r,n,True,json.dumps(dict(contacts=contacts)).encode(),b'{}',
                    ('unused','--mesh-listen',f'127.0.0.1:{42000+i}'))
        self.relays=[];self.owners={};self.signed_count=0;self.write_counts={'wallet-sign':0,'bft-submit':0}
        self.calls=[];self.processes={};self.terminal=[];self.cold=[];self.starts=0;self.unknowns=0;self.events=[];self.tls_observations=set(SLOTS)
        self.deadline=time.monotonic()+600;self.sequence=[];self.phase=None;self.fail_at=None
    def materialize(self):self.sequence.append('materialize')
    def file(self,name,value):return self.root/(name+'.json')
    def sign_original(self,label):
        self.sequence.append('owner-'+label);self.signed_count+=1;self.write_counts['wallet-sign']+=1;self.write_counts['bft-submit']+=1
        self.owners[label]=dict(signed=dict(intent_id='5'*64));return self.owners[label]['signed']
    def start(self,phase,slots):
        self.sequence.append(('start',phase,tuple(slots)))
        for s in slots:
            if s in self.processes:raise AssertionError('duplicate actual custody')
            self.processes[s]=object();self.starts+=1
    def wait(self,label,check):
        self.sequence.append(('wait',self.phase,len(self.processes),tuple(r.enabled for r in self.relays)))
        if self.fail_at==self.phase:raise ValueError('synthetic phase failure')
        return True
    def stop_all(self):self.sequence.append('stop');self.processes.clear()
    def record(self,kind,**data):self.sequence.append(kind)
    def stopped(self):
        self.sequence.append('full-cold');return {r:[dict(height=12)]*4 for r in REGIONS},dict(conserved=True)


class Tests(unittest.TestCase):
    def test_full_sequence_keeps_cut_through_offline_catchup_and_never_firstsigns_again(self):
        with tempfile.TemporaryDirectory(dir=PROJECT/'tmp',prefix='paged-fault-driver-model-') as tmp:
            model=Model(Path(tmp));Relay.instances=[]
            with patch('regional_paged_fault_driver.LiteralFaultRelay',Relay):result=model.run();model.cleanup()
            starts=[row for row in model.sequence if type(row) is tuple and row[0]=='start']
            self.assertEqual([len(row[2]) for row in starts],[11,1,12])
            self.assertNotIn(('earth',0),starts[0][2]);self.assertEqual(starts[1][2],(('earth',0),))
            waits=[row for row in model.sequence if type(row) is tuple and row[0]=='wait']
            self.assertEqual([row[1] for row in waits],list(PHASES))
            self.assertEqual([row[3] for row in waits],[(False,False),(False,False),(True,True),(True,True)])
            self.assertEqual(model.signed_count,3);self.assertEqual(result['ordinary_service_starts'],24)
            self.assertEqual((result['stage_seconds'],result['round_seconds'],result['new_height_limit']),(600,60,24))
            self.assertTrue(all(r.closed for r in Relay.instances));self.assertFalse(model.processes)
            self.assertLess(model.sequence.index('stop'),model.sequence.index('full-cold'))

    def test_failed_catchup_never_restores_contacts_or_replaces_owner_requests(self):
        with tempfile.TemporaryDirectory(dir=PROJECT/'tmp',prefix='paged-fault-driver-abort-') as tmp:
            model=Model(Path(tmp));model.fail_at=PHASES[1];Relay.instances=[]
            with patch('regional_paged_fault_driver.LiteralFaultRelay',Relay):
                with self.assertRaisesRegex(ValueError,'synthetic phase'):model.run()
                model.cleanup()
            self.assertEqual(model.signed_count,3);self.assertFalse(model.processes)
            self.assertTrue(all(r.closed and not r.enabled for r in Relay.instances))
            self.assertNotIn('full-cold',model.sequence)

    def test_original_owner_pending_and_response_survive_failure_without_replacement(self):
        with tempfile.TemporaryDirectory(dir=PROJECT/'tmp',prefix='paged-fault-driver-owner-') as tmp:
            root=Path(tmp);owner=root/'fault-owners/earth';(owner/'caller').mkdir(parents=True);(owner/'wallet').mkdir()
            pin=dict(currency='1'*64,region='2'*64,height=8,tip='3'*64,state='4'*64,finality='5'*64)
            request=dict(inputs=['6'*64]);review=dict(wallet_head='7'*64,review_commitment='8'*64,
                draft=dict(pin=pin,request=request,intent_id='9'*64))
            mesh.atomic(owner/'request.json',request);mesh.atomic(owner/'unsigned-review.json',review)
            mesh.atomic(owner/'wallet/wallet.json',dict(records=[]));mesh.atomic(owner/'caller/head.json',dict(head='7'*64,binding={},pending=None))
            driver=Driver.__new__(Driver);driver.root=root;driver.owners={};driver.processes={};driver.signed_count=0;driver.sequence=[]
            released=dict(previous_wallet_head='7'*64,wallet_head='a'*64,recovered_exact_retry=False,
                retained_approvals_complete=True,intent_id='9'*64,commands=[])
            saved={};calls=[]
            def call(label,n,command,*args):
                calls.append((label,n,command));self.assertEqual(n,1,'approval/queue must use online validator1')
                if command=='status':return pin
                if command=='wallet-sign':
                    pending=json.loads((owner/'caller/head.json').read_text())['pending']
                    self.assertEqual(pending,dict(intent_id='9'*64,review='8'*64));return released
                self.assertEqual(command,'bft-submit');self.assertEqual(saved['owners/earth/signed-response'],released)
                self.assertEqual(json.loads((owner/'caller/head.json').read_text())['head'],'a'*64)
                raise ValueError('synthetic lost queue response')
            driver.call=call;driver.record=lambda *args,**kw:None
            driver.file=lambda name,value:(saved.__setitem__(name,value),root/(name+'.json'))[1]
            with self.assertRaisesRegex(ValueError,'lost queue response'):driver.sign_original('earth')
            self.assertEqual(driver.signed_count,1);self.assertEqual(len([c for c in calls if c[2]=='wallet-sign']),1)
            self.assertEqual(json.loads((owner/'caller/head.json').read_text())['head'],'a'*64)
            # Partial output is retained. This failed driver is never retried.
            self.assertEqual(saved['owners/earth/signed-response'],released)

    def test_unknown_consensus_remains_unknown_and_tls_or_cap_changes_refuse(self):
        value=dict(process_id=123,currency='1'*64,relay_enabled=True,rejected=[],errors=[],
            consensus=dict(progress_observation_available=False,diagnostic='Native lock'),
            transport=dict(tcp=dict(encrypted=True,tls_version='TLSv1.3',fallback_to_plaintext=False,
                plaintext_selected_explicitly=False,tls_cert_sha256='2'*64,listener=dict(host='127.0.0.1',port=42000),
                limits=dict(inbound_workers=2,local_attempt_seconds=3.0,local_lock_wait_seconds=.2))))
        args=(123,'1'*64,'2'*64,dict(host='127.0.0.1',port=42000),27)
        self.assertIsNone(observation_height(value,*args))
        altered=copy.deepcopy(value);altered['transport']['tcp']['fallback_to_plaintext']=True
        with self.assertRaises(ValueError):observation_height(altered,*args)
        altered=copy.deepcopy(value);altered['consensus']=dict(height=28)
        with self.assertRaises(ValueError):observation_height(altered,*args)
        altered['consensus']=dict(height=True)
        with self.assertRaises(ValueError):observation_height(altered,*args)

    def test_later_certified_prefix_disagreement_cannot_pass_full_cold(self):
        statement=dict(currency='1'*64,region='2'*64,height=8,block='3'*64,state='4'*64,previous=None,epoch=None)
        state=dict(currency='1'*64,region='2'*64,height=8,tip='3'*64,state='4'*64,finality=statement_id(statement),ledger={})
        states=[copy.deepcopy(state) for _ in range(4)];proofs=[dict(snapshots=[dict(statement=statement)]) for _ in range(4)]
        self.assertEqual(compatible(states,proofs),8)
        states[-1]['ledger']=dict(coins={'forged':'claim'})
        with self.assertRaises(ValueError):compatible(states,proofs)
        states[-1]=copy.deepcopy(state);states[-1]['tip']='6'*64
        with self.assertRaises(ValueError):compatible(states,proofs)

    def test_wait_only_retries_known_native_lock_refusals(self):
        driver=Driver.__new__(Driver);driver.remaining=lambda:1;driver.observations=lambda:{};driver.record=lambda *a,**kw:None
        calls=[]
        def ready(_):
            calls.append(1)
            if len(calls)==1:raise NativeReadBusy('OS lock')
            return True
        with patch('regional_paged_fault_driver.time.sleep'):self.assertTrue(driver.wait('check',ready))
        self.assertEqual(len(calls),2)
        with self.assertRaisesRegex(ValueError,'bad owner'):
            driver.wait('check',lambda _:(_ for _ in ()).throw(ValueError('bad owner signature')))

    def test_controller_cannot_vote_initialize_recover_or_extend_total_budget(self):
        driver=Driver.__new__(Driver)
        with patch('regional_paged_fault_driver.subprocess.run',side_effect=AssertionError('Native must stay closed')):
            for command in ('mine','accept','finalize','bft-sign','bft-certify','bft-sync','wallet-init','wallet-recover','bft-recover'):
                with self.subTest(command=command),self.assertRaises(ValueError):driver.call('earth',1,command)
            bound=Bound('/unused-root','/unused-output','1'*64,(),12,9,'2'*64)
            for deadline in (time.monotonic()+601,time.monotonic()-1,float('nan')):
                with self.assertRaises(ValueError):Driver(PROJECT,bound,deadline,lambda *a:None)

    def test_manifest_advance_never_hides_rewritten_missing_old_voter_pages(self):
        old={'bft-header.json':['header',1], 'bft-records/pages/old.json':['exact-complete-old-bytes',2],
            'bft-records/stream.json':['old-manifest',3]}
        newer=copy.deepcopy(old);newer['bft-records/stream.json']=['new-manifest',4]
        newer['bft-records/pages/new.json']=['exact-new-bytes',5]
        retain_original_objects(old,newer,'bft-records/stream.json')
        bad=copy.deepcopy(newer);del bad['bft-records/pages/old.json']
        with self.assertRaises(ValueError):retain_original_objects(old,bad,'bft-records/stream.json')
        bad=copy.deepcopy(newer);bad['bft-records/pages/old.json']=['different-but-authenticated-variant',2]
        with self.assertRaises(ValueError):retain_original_objects(old,bad,'bft-records/stream.json')
        with self.assertRaises(ValueError):retain_original_objects(old,newer,'not-a-retained-manifest')


if __name__=='__main__':unittest.main()
