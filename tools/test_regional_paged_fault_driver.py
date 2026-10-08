"""Refuse unsafe driver transitions; no Native, Runtime, sign or socket is run."""
import copy
from types import SimpleNamespace
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
from regional_paged_fault_driver import Driver, NativeReadBusy, NativeReceiptNotObserved, receipt_not_observed, native_read_busy, NATIVE_BUSY_DIAGNOSTICS, SERVICE_NATIVE_BUSY_DIAGNOSTICS, observation_height, compatible, statement_id, retain_original_objects
from regional_paged_fault_launch import Config, PHASES, SLOTS, encoded
from regional_bft_node import private
from regional_paged_fault_scope import REGIONS, inventory
from regional_paged_fault_prepared import Bound

PROJECT=Path(__file__).resolve().parents[1]


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
    def prepare_keyless_startup(self):self.sequence.append('startup-pins')
    def record(self,kind,**data):self.sequence.append(kind)
    def stopped_drain(self):
        if self.processes:raise AssertionError('model fixed-head drain before stop')
        self.sequence.append('stopped-drain');return True
    def stopped(self):
        self.sequence.append('full-cold');return {r:[dict(height=12)]*4 for r in REGIONS},dict(conserved=True)


class Tests(unittest.TestCase):
    def test_loop_read_refuses_changed_heads_authority_and_incomplete_messages(self):
        d=Driver.__new__(Driver)
        caller=dict(head='1'*64,binding={'region':'fixture'})
        config=dict(signer_dir='/never-opened')
        valid=dict(format='RLD-BFT-LOOP-RETAINED-OBSERVATION-V1',native={'context':{}},
            signer=dict(head=caller['head'],binding=caller['binding']),retained_messages=[],
            signing_authority=False,independent_freshness_qualified=False)
        seen=[]
        def response(*args):seen.append(args);return copy.deepcopy(valid)
        d.call=response
        self.assertEqual(d.loop_read('earth',0,config,caller,True)['retained_messages'],[])
        self.assertEqual(seen[-1],('earth',0,'bft-loop-status','--signer-dir',config['signer_dir'],
            '--expected-head',caller['head'],'--include-retained-messages'))
        for why in ('head','binding','authority','freshness','messages','format','missing'):
            value=copy.deepcopy(valid)
            if why=='head':value['signer']['head']='2'*64
            elif why=='binding':value['signer']['binding']={}
            elif why=='authority':value['signing_authority']=True
            elif why=='freshness':value['independent_freshness_qualified']=True
            elif why=='messages':value['retained_messages']=False
            elif why=='format':value['format']='RLD-BFT-LOOP-OBSERVATION-V1'
            else:value.pop('retained_messages')
            d.call=lambda *args:copy.deepcopy(value)
            with self.subTest(why=why),self.assertRaises(ValueError):d.loop_read('earth',0,config,caller,True)

    def test_loop_adapter_classifies_only_exact_read_lock_as_unknown(self):
        driver=Driver.__new__(Driver);driver.project=PROJECT;driver.root=PROJECT/'tmp/unused-no-native'
        driver.authority='1'*64;driver.currency='2'*64;driver.calls=[];driver.remaining=lambda:1
        driver.configs={(PHASES[0],'earth',1):Config(PHASES[0],'earth',1,True,b'{}',b'{}',('/not-run',))}
        driver.write_counts={}
        def reply(message):
            def fake_run(*args,**kw):kw['stderr'].write(message);return SimpleNamespace(returncode=1)
            return fake_run
        text=b'regional candidate rejected: BFT signer is already locked\n'
        with patch('regional_paged_fault_driver.subprocess.run',reply(text)):
            with self.assertRaises(NativeReadBusy):driver.call('earth',1,'bft-loop-status')
        with patch('regional_paged_fault_driver.subprocess.run',reply(text+b'bad signature')):
            with self.assertRaises(ValueError) as error:driver.call('earth',1,'bft-loop-status')
            self.assertNotIsInstance(error.exception,NativeReadBusy)
        self.assertFalse(driver.write_counts)

    def test_observed_cold_read_adapter_keeps_lock_unknown_and_other_refusals_fatal(self):
        driver=Driver.__new__(Driver);driver.project=PROJECT;driver.root=PROJECT/'tmp/unused-no-native'
        driver.authority='1'*64;driver.currency='2'*64;driver.calls=[];driver.remaining=lambda:1
        driver.configs={(PHASES[0],'earth',1):Config(PHASES[0],'earth',1,True,b'{}',b'{}',('/not-run',))}
        driver.write_counts={}
        command='bft-network-check-plan-observed'
        def respond(message,code=1):
            def fake_run(*args,**kw):
                self.assertEqual(args[0][-1],command);self.assertEqual(kw['cwd'],PROJECT)
                kw['stderr'].write(message);return SimpleNamespace(returncode=code)
            return fake_run
        diagnostic=b'regional candidate rejected: complete stream already locked\n'
        with patch('regional_paged_fault_driver.subprocess.run',respond(diagnostic)):
            with self.assertRaises(NativeReadBusy):driver.call('earth',1,command)
            self.assertEqual(driver.calls[-1]['observation_kind'],'NATIVE_READ_BUSY')
        for text,code in [(diagnostic+b' '*3000+b'invalid checkpoint proof\n',1),
                (b'regional candidate rejected: invalid proof: already locked\n',1),
                (b'regional candidate rejected: network plan head differs\n',1),
                (diagnostic,2)]:
            with self.subTest(text=text,code=code),patch('regional_paged_fault_driver.subprocess.run',respond(text,code)):
                with self.assertRaises(ValueError) as error:driver.call('earth',1,command)
                self.assertNotIsInstance(error.exception,NativeReadBusy)
                self.assertEqual(driver.calls[-1]['observation_kind'],'FATAL_NATIVE_REFUSAL')
        self.assertFalse(driver.write_counts);self.assertEqual(len(driver.calls),5)

    def test_stopped_observed_plan_precedes_unpinned_reads_and_binds_exact_head(self):
        driver=Driver.__new__(Driver);driver.processes={};driver.root=PROJECT/'tmp/unused-no-native'
        driver.currency='2'*64;head={'history_head':'3'*64};captured=[]
        driver.phase=PHASES[-1];driver.deadline=time.monotonic()+600
        driver.terminal=[dict(region=label,index=n,exit_code=0) for label,n in SLOTS]
        def pin(label,n,prefix):captured.append((label,n));return head
        driver.pin_head=pin;driver.configs={}
        for label,n in SLOTS:
            conf=dict(state=str(driver.root/f'state-{label}-{n}'),signer_dir=str(driver.root/f'signer-{label}-{n}'),
                head_file=str(driver.root/f'caller-{label}-{n}.json'))
            driver.configs[PHASES[-1],label,n]=Config(PHASES[-1],label,n,True,b'{}',json.dumps(conf).encode(),('/not-run',))
        driver.call=lambda *args:self.fail('unpinned Native read before complete observed pinned plan')
        class StopAtObserved(Exception):pass
        def observed(native,config,root,pin):
            self.assertEqual(set(captured),set(SLOTS));self.assertEqual(len(captured),12)
            self.assertEqual((root,pin),(driver.root,head['history_head']))
            self.assertTrue(config['state'].startswith(str(driver.root/'state-')))
            self.assertEqual(native.currency,driver.currency)
            raise StopAtObserved
        with patch('regional_paged_fault_driver.inventory',return_value={}),patch(
                'regional_paged_fault_driver.verify_stopped_state_pinned_observed',observed,create=True):
            with self.assertRaises(StopAtObserved):driver.stopped()

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
            self.assertLess(model.sequence.index('stopped-drain'),model.sequence.index('full-cold'))
            self.assertEqual(model.sequence[model.sequence.index('stopped-drain')-1],'stop')

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

    def test_exact_missing_native_receipt_is_unknown_never_authentication_success(self):
        diagnostic='regional candidate rejected: wallet has no independently verified evidence for this export\n'
        self.assertTrue(receipt_not_observed('wallet-receipt',1,diagnostic))
        for command,code,error in [('status',1,diagnostic),('wallet-receipt',2,diagnostic),
            ('wallet-receipt',True,diagnostic),('wallet-receipt',1,diagnostic+'bad signature'),
            ('wallet-receipt',1,'regional candidate rejected: wallet receipt domain mismatch'),
            ('wallet-receipt',1,'regional candidate rejected: invalid checkpoint proof')]:
            with self.subTest(command=command,error=error):self.assertFalse(receipt_not_observed(command,code,error))
        driver=Driver.__new__(Driver);driver.remaining=lambda:1;driver.observations=lambda:{};driver.record=lambda *a,**kw:None
        seen=[]
        def read(_):
            seen.append(1)
            if len(seen)==1:raise NativeReceiptNotObserved('no retained evidence at this replica yet')
            return 'actual later fresh observation'
        with patch('regional_paged_fault_driver.time.sleep'):
            self.assertEqual(driver.wait('receipt',read),'actual later fresh observation')
        self.assertEqual(len(seen),2)

    def test_actual_call_path_reproduces_absence_refusal_and_keeps_bad_proof_fatal(self):
        from types import SimpleNamespace
        driver=Driver.__new__(Driver);driver.project=PROJECT;driver.root=PROJECT/'tmp/unused-no-native';driver.authority='1'*64
        driver.currency='2'*64;driver.configs={(PHASES[0],'proxima',0):Config(PHASES[0],'proxima',0,True,b'{}',b'{}',('/not-run',))}
        driver.calls=[];driver.remaining=lambda:1;driver.write_counts={}
        def respond(message):
            def fake_run(*args,**kw):kw['stderr'].write(message);return SimpleNamespace(returncode=1)
            return fake_run
        diagnostic=b'regional candidate rejected: wallet has no independently verified evidence for this export\n'
        with patch('regional_paged_fault_driver.subprocess.run',respond(diagnostic)):
            with self.assertRaises(NativeReceiptNotObserved):driver.call('proxima',0,'wallet-receipt','--file','not-run')
            with self.assertRaises(ValueError) as error:driver.call('proxima',0,'status')
            self.assertNotIsInstance(error.exception,NativeReceiptNotObserved)
        with patch('regional_paged_fault_driver.subprocess.run',respond(b'regional candidate rejected: invalid checkpoint proof\n')):
            with self.assertRaises(ValueError) as error:driver.call('proxima',0,'wallet-receipt','--file','not-run')
            self.assertNotIsInstance(error.exception,NativeReceiptNotObserved)
        self.assertFalse(driver.write_counts);self.assertEqual(len(driver.calls),3)
        self.assertEqual([c['observation_kind'] for c in driver.calls],
            ['NATIVE_RECEIPT_NOT_OBSERVED','FATAL_NATIVE_REFUSAL','FATAL_NATIVE_REFUSAL'])

    def test_later_error_after_2048bytes_cannot_be_hidden_by_absence_prefix(self):
        from types import SimpleNamespace
        driver=Driver.__new__(Driver);driver.project=PROJECT;driver.root=PROJECT/'tmp/unused-no-native';driver.authority='1'*64
        driver.currency='2'*64;driver.configs={(PHASES[0],'proxima',0):Config(PHASES[0],'proxima',0,True,b'{}',b'{}',('/not-run',))}
        driver.calls=[];driver.remaining=lambda:1;driver.write_counts={}
        diagnostic=b'regional candidate rejected: wallet has no independently verified evidence for this export'+b' '*3000+b'\ninvalid checkpoint proof\n'
        def fake_run(*args,**kw):kw['stderr'].write(diagnostic);return SimpleNamespace(returncode=1)
        with patch('regional_paged_fault_driver.subprocess.run',fake_run):
            with self.assertRaises(ValueError) as error:driver.call('proxima',0,'wallet-receipt','--file','not-run')
            self.assertNotIsInstance(error.exception,NativeReceiptNotObserved)

    def test_only_exact_known_native_read_lock_diagnostics_are_unknown(self):
        for diagnostic in NATIVE_BUSY_DIAGNOSTICS:
            self.assertTrue(native_read_busy('status',1,diagnostic+'\n'))
            self.assertTrue(native_read_busy('bft-status',1,diagnostic))
            for command,code,text in [('wallet-sign',1,diagnostic),('bft-submit',1,diagnostic),
                ('status',2,diagnostic),('status',True,diagnostic),('status',1,diagnostic+'\nbad signature'),
                ('status',1,'regional candidate rejected: invalid proof: already locked'),
                ('status',1,'regional candidate rejected: Permission denied (os error 13)')]:
                with self.subTest(command=command,text=text):self.assertFalse(native_read_busy(command,code,text))

    def test_actual_read_adapter_handles_would_block_without_hiding_bad_proof_or_writes(self):
        from types import SimpleNamespace
        driver=Driver.__new__(Driver);driver.project=PROJECT;driver.root=PROJECT/'tmp/unused-no-native';driver.authority='1'*64
        driver.currency='2'*64;driver.configs={(PHASES[0],'earth',1):Config(PHASES[0],'earth',1,True,b'{}',b'{}',('/not-run',))}
        driver.calls=[];driver.remaining=lambda:1;driver.write_counts={}
        diagnostic=b'regional candidate rejected: lock acquisition failed because the operation would block\n'
        def respond(message):
            def fake_run(*args,**kw):kw['stderr'].write(message);return SimpleNamespace(returncode=1)
            return fake_run
        with patch('regional_paged_fault_driver.subprocess.run',respond(diagnostic)):
            with self.assertRaises(NativeReadBusy):driver.call('earth',1,'status')
            self.assertEqual(driver.calls[-1]['observation_kind'],'NATIVE_READ_BUSY')
            with self.assertRaises(ValueError) as error:driver.call('earth',1,'wallet-sign')
            self.assertNotIsInstance(error.exception,NativeReadBusy)
        with patch('regional_paged_fault_driver.subprocess.run',respond(diagnostic+b' '*3000+b'invalid checkpoint proof\n')):
            with self.assertRaises(ValueError) as error:driver.call('earth',1,'status')
            self.assertNotIsInstance(error.exception,NativeReadBusy)
        self.assertFalse(driver.write_counts)


    def test_exact_runtime_native_lock_is_whole_observation_unknown_even_with_height(self):
        value=dict(process_id=123,currency='1'*64,relay_enabled=True,rejected=[],errors=[],
            consensus=dict(height=9),transport=dict(progress_observation_available=False))
        args=(123,'1'*64,'2'*64,dict(host='127.0.0.1',port=42000),27)
        for diagnostic in SERVICE_NATIVE_BUSY_DIAGNOSTICS:
            observed=copy.deepcopy(value);observed['errors']=[diagnostic]
            self.assertIsNone(observation_height(observed,*args))
        self.assertEqual(observation_height(value,*args),9)
        observed=copy.deepcopy(value);observed['errors']=[next(iter(SERVICE_NATIVE_BUSY_DIAGNOSTICS))]
        observed['consensus']=dict(progress_observation_available=False)
        self.assertIsNone(observation_height(observed,*args))

    def test_runtime_lock_never_hides_rejection_bad_proof_persistence_or_tls_errors(self):
        diagnostic='native rejected: regional candidate rejected: lock acquisition failed because the operation would block'
        value=dict(process_id=123,currency='1'*64,relay_enabled=True,rejected=[],errors=[diagnostic],
            consensus=dict(height=9),transport=dict(progress_observation_available=False))
        args=(123,'1'*64,'2'*64,dict(host='127.0.0.1',port=42000),27)
        for errors,rejections in [([diagnostic+'\ninvalid proof'],[]),
            ([diagnostic,'native rejected: invalid owner/domain/signature'],[]),
            ([diagnostic,'BFT runtime requires restart after persistence failure'],[]),
            ([diagnostic], [{'packet_id':'3'*64,'reason':diagnostic}]),
            (['native rejected: regional candidate rejected: invalid proof: already locked'],[])]:
            observed=copy.deepcopy(value);observed['errors']=errors;observed['rejected']=rejections
            with self.subTest(errors=errors,rejections=rejections):
                with self.assertRaises(ValueError):observation_height(observed,*args)
        for height in (28,True,-1):
            observed=copy.deepcopy(value);observed['consensus']=dict(height=height)
            with self.subTest(height=height):
                with self.assertRaises(ValueError):observation_height(observed,*args)
        value['transport']=dict(tcp=dict(encrypted=False))
        with self.assertRaises(ValueError):observation_height(value,*args)


    def test_complete_native_recipient_read_does_not_require_global_known_telemetry(self):
        driver=Driver.__new__(Driver);driver.expectation=dict(export='3'*64)
        driver.expectation_path=Path('/not-run');driver.calls=[];retained=[];attempts=[]
        value=dict(expected=driver.expectation,evidence_verified=True,import_accepted=True,
            maturity_reached=True,original_output_spendable_now=True,original_output_remaining='9',
            local_finality_covers_import=True,quarantined=False)
        def call(*args):attempts.append(args);driver.calls.append(dict(command='wallet-receipt'));return value
        driver.call=call;driver.file=lambda name,record:retained.append((name,record))
        heights={s:None for s in SLOTS};before=copy.deepcopy(heights)
        with patch('regional_paged_fault_driver.time.monotonic',return_value=10):
            self.assertEqual(driver.live_receipt(heights),value)
            self.assertFalse(driver.live_receipt(heights))
        self.assertEqual(attempts,[('proxima',0,'wallet-receipt','--file',driver.expectation_path)])
        self.assertEqual(heights,before);self.assertEqual(driver.receipt_slot,1)
        self.assertEqual(retained,[('observations/original-receipt-1',dict(region='proxima',index=0,call_index=0,receipt=value))])

    def test_receipt_rotation_retains_unknown_pending_and_wrong_binding_without_credit(self):
        driver=Driver.__new__(Driver);driver.expectation=dict(export='3'*64)
        driver.expectation_path=Path('/not-run');driver.calls=[];retained=[];slots=[]
        pending=dict(expected=driver.expectation,evidence_verified=True,import_accepted=False,
            maturity_reached=False,original_output_spendable_now=False,original_output_remaining='0',
            local_finality_covers_import=False,quarantined=False)
        def call(label,n,*args):
            slots.append(n);driver.calls.append(dict(command='wallet-receipt'))
            if n==0:raise NativeReadBusy('exact native lock unknown')
            if n==1:raise NativeReceiptNotObserved('exact native evidence not observed')
            if n==3:return dict(pending,expected=dict(export='4'*64))
            return pending
        driver.call=call;driver.file=lambda name,record:retained.append((name,record))
        heights={s:None for s in SLOTS}
        with patch('regional_paged_fault_driver.time.monotonic',return_value=10):
            with self.assertRaises(NativeReadBusy):driver.live_receipt(heights)
        with patch('regional_paged_fault_driver.time.monotonic',return_value=12):
            with self.assertRaises(NativeReceiptNotObserved):driver.live_receipt(heights)
        with patch('regional_paged_fault_driver.time.monotonic',return_value=14):self.assertFalse(driver.live_receipt(heights))
        with patch('regional_paged_fault_driver.time.monotonic',return_value=16):
            with self.assertRaisesRegex(ValueError,'exact original receipt binding'):driver.live_receipt(heights)
        self.assertEqual(slots,[0,1,2,3]);self.assertEqual(driver.receipt_slot,0)
        self.assertEqual(len(retained),1);self.assertEqual(retained[0][1]['receipt'],pending)
        self.assertFalse(retained[0][1]['receipt']['import_accepted'])


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
        with tempfile.TemporaryDirectory(dir=PROJECT/'tmp') as t:
            d,p,v=self.setup_model(Path(t));before=p.read_bytes();d.stop_all();self.restart(d)
            self.assertEqual(d.observations(),{('earth',0):None});self.assertEqual(d.unknowns,1)
            self.assertFalse(d.tls_observations);self.assertEqual(p.read_bytes(),before)
            v['process_id']=102;v['consensus']['autonomous_signing_enabled']=False;mesh.atomic(p,v)
            self.assertEqual(d.observations(),{('earth',0):12});self.assertEqual(d.tls_observations,{('earth',0)})
            p.write_bytes(before)
            with self.assertRaisesRegex(ValueError,'another process/domain'):d.observations()
    def test_reused_pid_does_not_credit_unchanged_signing_observation(self):
        with tempfile.TemporaryDirectory(dir=PROJECT/'tmp') as t:
            d,p,v=self.setup_model(Path(t));d.stop_all();self.restart(d,101)
            self.assertEqual(d.observations(),{('earth',0):None});self.assertFalse(d.tls_observations)
            v['consensus']['autonomous_signing_enabled']=False;mesh.atomic(p,v)
            self.assertEqual(d.observations(),{('earth',0):12})
    def test_changed_old_pid_other_domain_or_slot_remains_fatal(self):
        for change in ('bytes','currency','region','slot'):
            with self.subTest(change=change),tempfile.TemporaryDirectory(dir=PROJECT/'tmp') as t:
                d,p,v=self.setup_model(Path(t));d.stop_all();self.restart(d)
                if change=='bytes':p.write_bytes(p.read_bytes()+b'\n')
                elif change=='slot':d.stopped_observations[('earth',1)]=d.stopped_observations.pop(('earth',0))
                else:v[change]='9'*64;mesh.atomic(p,v)
                with self.assertRaises(ValueError):d.observations()
    def test_no_clean_own_stop_never_accepts_foreign_status(self):
        for reason in ('unowned','unclean','wrong-domain','invalid-TLS'):
            with self.subTest(reason=reason),tempfile.TemporaryDirectory(dir=PROJECT/'tmp') as t:
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
            with self.subTest(change=change),tempfile.TemporaryDirectory(dir=PROJECT/'tmp') as t:
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
        with tempfile.TemporaryDirectory(dir=PROJECT/'tmp') as t:
            d,p,v=self.setup_model(Path(t));d.stop_all();self.restart(d)
            d.processes[('earth',0)].poll=lambda:1
            with self.assertRaisesRegex(ValueError,'exited prematurely'):d.observations()
            self.restart(d);d.deadline=0
            with self.assertRaisesRegex(ValueError,'budget exhausted'):d.wait('new-pid',lambda h:False)

    def test_exact_shutdown_marker_only_after_clean_stop_is_unknown(self):
        with tempfile.TemporaryDirectory(dir=PROJECT/'tmp') as t:
            d,p,v=self.setup_model(Path(t));v['errors']=['TCP runtime is stopping; preserve evidence'];mesh.atomic(p,v)
            before=p.read_bytes();d.stop_all();self.restart(d)
            self.assertEqual(d.observations(),{('earth',0):None});self.assertFalse(d.tls_observations)
            self.assertEqual(p.read_bytes(),before)
            v['process_id']=102;v['consensus']['autonomous_signing_enabled']=False;mesh.atomic(p,v)
            with self.assertRaisesRegex(ValueError,'actual Native/Service error'):d.observations()
            v['errors']=[];mesh.atomic(p,v);self.assertEqual(d.observations(),{('earth',0):12})
    def test_shutdown_marker_never_hides_other_stop_errors(self):
        for error in ('native rejected: invalid complete finality proof','[Errno 22] Invalid argument','TCP runtime is stopping; preserve evidence extra','regional candidate rejected: Permission denied (os error 13)'):
            with self.subTest(error=error),tempfile.TemporaryDirectory(dir=PROJECT/'tmp') as t:
                d,p,v=self.setup_model(Path(t));v['errors']=['TCP runtime is stopping; preserve evidence',error];mesh.atomic(p,v)
                d.stop_all();self.assertFalse(d.stopped_observations);self.restart(d)
                with self.assertRaises(ValueError):d.observations()
        with tempfile.TemporaryDirectory(dir=PROJECT/'tmp') as t:
            d,p,v=self.setup_model(Path(t));v['errors']=['TCP runtime is stopping; preserve evidence'];v['rejected']=['complete envelope'];mesh.atomic(p,v)
            d.stop_all();self.assertFalse(d.stopped_observations);self.restart(d)
            with self.assertRaises(ValueError):d.observations()

class KeylessDirectoryTests(unittest.TestCase):
    def model(self, directory):
        d=Driver.__new__(Driver);d.root=directory/'root';d.root.mkdir(mode=0o700);d.output=directory/'output';d.currency='1'*64;d.deadline=time.monotonic()+600
        d.mesh_anchors={s:dict(public_key='2'*64,node_id='3'*64,network=d.currency,config_sha256='4'*64) for s in SLOTS}
        d.configs={}
        for phase in PHASES:
            for label,n in SLOTS:
                key=d.root/'keyless-absent'/f'{label}-{n}.json' if phase==PHASES[-1] else d.root/label/f'public-fixture-key-{n}.json'
                d.configs[phase,label,n]=Config(phase,label,n,True,encoded({}),encoded(dict(key_file=str(key))),('never-executed',))
        d.bound=SimpleNamespace(configs=tuple(d.configs.values()),preparation_inventory='5'*64);d.prepared_inventory=inventory(d.root);d.fake_reads=[]
        def status(label,n,command,*args):
            self.assertEqual(command,'status');d.fake_reads.append((label,n));return {'modeled_only':True}
        d.call=status
        return d
    def test_actual_materialization_all12_private_missing_key_paths_without_any_key(self):
        with tempfile.TemporaryDirectory(dir=PROJECT/'tmp',prefix='keyless-directory-model-') as t:
            d=self.model(Path(t));d.materialize();parent=d.root/'keyless-absent'
            for label,n in SLOTS:
                key=parent/f'{label}-{n}.json';self.assertEqual(private(key,missing=True),key);self.assertFalse(key.exists())
            self.assertEqual(parent.stat().st_mode&0o777,0o700);self.assertEqual(list(parent.iterdir()),[])
            self.assertEqual(d.fake_reads,list(SLOTS))
            with self.assertRaises(ValueError):d.materialize()
    def test_foreign_key_paths_and_preexisting_directory_refuse_before_fake_native_reads(self):
        for reason in ('existing','foreign','symlink'):
            with self.subTest(reason=reason),tempfile.TemporaryDirectory(dir=PROJECT/'tmp',prefix='keyless-directory-model-') as t:
                d=self.model(Path(t));p=d.root/'keyless-absent'
                if reason=='existing':p.mkdir(mode=0o700)
                elif reason=='symlink':p.symlink_to(d.root/'elsewhere',target_is_directory=True)
                else:
                    c=d.configs[PHASES[-1],'earth',0];d.configs[PHASES[-1],'earth',0]=Config(c.phase,c.region,c.index,c.started,c.mesh,json.dumps(dict(key_file=str(d.root/'earth/public-fixture-key-0.json'))).encode(),c.argv)
                with self.assertRaises((ValueError,FileExistsError)):d.prepare_keyless_directory()
                self.assertFalse(d.fake_reads)
    def test_original_runtime_private_permissions_and_symlink_guards_still_refuse(self):
        with tempfile.TemporaryDirectory(dir=PROJECT/'tmp',prefix='keyless-directory-model-') as t:
            d=self.model(Path(t));d.materialize();p=d.root/'keyless-absent';p.chmod(0o755)
            with self.assertRaises(ValueError):private(p/'earth-0.json',missing=True)
            p.chmod(0o700);(p/'earth-0.json').symlink_to(p/'nonexistent')
            with self.assertRaises(ValueError):private(p/'earth-0.json',missing=True)

class StoppedDrainTests(unittest.TestCase):
 def model(self,p):
  d=Driver.__new__(Driver);d.currency='1'*64;d.regions={label:str(i+2)*64 for i,label in enumerate(REGIONS)};d.deadline=time.monotonic()+600;d.phase=PHASES[-1];d.processes={};d.terminal=[dict(region=l,index=n,exit_code=0) for l,n in SLOTS];d.configs={};d.queries=[];d.closed=False;d.heights={slot:17 if slot[0]=='earth' else 15 for slot in SLOTS};d.native_heights=dict(d.heights);d.pending=False;d.group=False;d.foreign=False
  from regional_bft_keyless_drain import current_commits
  d.keyless_drains={}
  for label,n in SLOTS:
   key=f'{n+1:064x}'
   caller=p/f'{label}-{n}.json';caller.write_text(json.dumps(dict(pending=None,outbox=None,head='3'*64,binding='4'*64)));d.configs[PHASES[-1],label,n]=Config(PHASES[-1],label,n,True,encoded({}),encoded(dict(key=key,head_file=str(caller),signer_dir=str(p/f'never-opened-{label}-{n}'))),('never-executed',))
   context=dict(currency=d.currency,region=d.regions[label],epoch='5'*64,previous=None,
                parent_height=d.heights[label,n],parent_block='6'*64,parent_state='7'*64)
   d.keyless_drains[label,n]=current_commits(context,[],key,'3'*64)
  def call(label,n,command,*args):
   d.queries.append((label,n,command))
   if not d.closed and (label,n,command)==('earth',1,'bft-loop-status'):raise NativeReadBusy('model exact live lock refusal')
   if command=='bft-loop-status':
    context=dict(parent_height=d.native_heights[label,n],currency=d.currency,region=d.regions[label],round=1)
    messages=[dict(Vote=dict(phase='Commit',context=context,round=1,value='5'*64,approval={'key':str(i)})) for i in range(3)] if d.group else []
    return dict(format='RLD-BFT-LOOP-RETAINED-OBSERVATION-V1',native=dict(context=context),signer=dict(head='3'*64,binding='4'*64),retained_messages=messages,signing_authority=False,independent_freshness_qualified=False)
   if command=='status':return dict(currency='9'*64 if d.foreign else d.currency,region=d.regions[label],height=d.native_heights[label,n])
   if command=='bft-context':return {'context':dict(parent_height=d.native_heights[label,n],currency=d.currency,region=d.regions[label],round=1)}
   if command=='bft-status':return dict(head='3'*64,binding='4'*64)
   if command=='bft-retained-messages':
    context=dict(parent_height=d.native_heights[label,n],currency=d.currency,region=d.regions[label],round=1)
    return [dict(Vote=dict(phase='Commit',context=context,round=1,value='5'*64,approval={'key':str(i)})) for i in range(3)] if d.group else []
   raise AssertionError(command)
  d.call=call;return d
 def test_actual_live_drain_restarts_prefix_under_later_read_lock(self):
  with tempfile.TemporaryDirectory(dir=PROJECT/'tmp',prefix='drain-model-') as t:
   d=self.model(Path(t));success=False
   for _ in range(5):
    try:success=bool(d.drain_ready(d.heights))
    except NativeReadBusy:pass
   self.assertFalse(success);self.assertEqual(sum(q==('earth',0,'bft-loop-status') for q in d.queries),5);self.assertFalse(any(q[0]!='earth' for q in d.queries))
 def test_same_original_drain_predicate_after_clean_stop_checks_all12(self):
  with tempfile.TemporaryDirectory(dir=PROJECT/'tmp',prefix='drain-model-') as t:
   d=self.model(Path(t));d.closed=True;self.assertTrue(d.stopped_drain());self.assertEqual({(l,n) for l,n,c in d.queries if c=='bft-loop-status'},set(SLOTS));self.assertEqual(sum(c=='status' for l,n,c in d.queries),12)
 def test_live_process_unclean_stop_or_wrong_phase_refuse_before_read(self):
  for why in ('live','unclean','phase','incomplete'):
   with self.subTest(why=why),tempfile.TemporaryDirectory(dir=PROJECT/'tmp',prefix='drain-model-') as t:
    d=self.model(Path(t));d.closed=True
    if why=='live':d.processes[('earth',0)]=SimpleNamespace()
    if why=='unclean':d.terminal[-1]['exit_code']=-15
    if why=='phase':d.phase=PHASES[0]
    if why=='incomplete':d.terminal=d.terminal[:-1]
    with self.assertRaises(ValueError):d.stopped_drain()
    self.assertFalse(d.queries)
 def test_unknown_telemetry_and_unequal_replica_observations_cannot_trigger_stop(self):
  with tempfile.TemporaryDirectory(dir=PROJECT/'tmp',prefix='drain-model-') as t:
   d=self.model(Path(t));self.assertTrue(d.keyless_observations_ready(d.heights));h=dict(d.heights);h['earth',0]=None;self.assertFalse(d.keyless_observations_ready(h));h['earth',0]=18;self.assertFalse(d.keyless_observations_ready(h));h['earth',0]=True;self.assertFalse(d.keyless_observations_ready(h))
 def test_same_height_complete_native_commit_group_or_missing_report_cannot_trigger_stop(self):
  for why in ('group','missing','changed-caller','pending','context'):
   with self.subTest(why=why),tempfile.TemporaryDirectory(dir=PROJECT/'tmp') as t:
    d=self.model(Path(t));self.assertTrue(d.keyless_observations_ready(d.heights));d.queries.clear()
    if why=='group':
     for n in (0,1,2):d.keyless_drains['earth',n]['commits']=[dict(round=0,value='8'*64,key=f'{n+1:064x}')]
    elif why=='missing':d.keyless_drains.pop(('earth',0))
    elif why=='context':d.keyless_drains['earth',0]['context']['parent_height']+=1
    else:
     path=Path(json.loads(d.configs[PHASES[-1],'earth',0].bft)['head_file']);caller=json.loads(path.read_text())
     if why=='pending':caller['pending']={}
     else:caller['head']='9'*64
     path.write_text(json.dumps(caller))
    self.assertFalse(d.keyless_observations_ready(d.heights));self.assertEqual(d.queries,[])
 def test_native_domain_cap_and_divergence_do_not_receive_drain_credit(self):
  for why in ('foreign','region','cap','different'):
   with self.subTest(why=why),tempfile.TemporaryDirectory(dir=PROJECT/'tmp',prefix='drain-model-') as t:
    d=self.model(Path(t));d.closed=True
    if why=='foreign':d.foreign=True
    elif why=='cap':d.native_heights['earth',0]=28
    elif why=='different':d.native_heights['earth',0]=18
    else:
     old=d.call
     def wrong(*args):
      v=old(*args)
      if args[2]=='status':v['region']='9'*64
      return v
     d.call=wrong
    if why=='different':self.assertFalse(d.stopped_drain())
    else:
     with self.assertRaises(ValueError):d.stopped_drain()
 def test_pending_caller_head_and_complete_commit_group_remain_refusals(self):
  for why in ('pending','outbox','head','group'):
   with self.subTest(why=why),tempfile.TemporaryDirectory(dir=PROJECT/'tmp',prefix='drain-model-') as t:
    d=self.model(Path(t));d.closed=True;c=json.loads(d.configs[PHASES[-1],'earth',0].bft);p=Path(c['head_file']);v=json.loads(p.read_text())
    if why in ('pending','outbox'):v[why]={};p.write_text(json.dumps(v));self.assertFalse(d.stopped_drain())
    elif why=='head':v['head']='5'*64;p.write_text(json.dumps(v));
    if why=='head':
     with self.assertRaises(ValueError):d.stopped_drain()
    if why=='group':d.group=True;self.assertFalse(d.stopped_drain())

class StoppedReaderPoolTests(unittest.TestCase):
    def model(self,root):
        return StoppedDrainTests().model(root)
    def test_all12_results_keep_order_and_two_reader_bound(self):
        import threading
        with tempfile.TemporaryDirectory(dir=PROJECT/'tmp',prefix='stopped-reader-model-') as tmp:
            driver=self.model(Path(tmp));lock=threading.Lock();barrier=threading.Barrier(2)
            active=0;maximum=0;completed=[]
            def read(label,n):
                nonlocal active,maximum
                with lock:active+=1;maximum=max(maximum,active)
                try:
                    barrier.wait(timeout=2)
                    return label,n
                finally:
                    with lock:active-=1;completed.append((label,n))
            self.assertEqual(driver.stopped_reads(SLOTS,read),list(SLOTS))
            self.assertEqual(maximum,2);self.assertEqual(active,0);self.assertEqual(set(completed),set(SLOTS))
    def test_any_refusal_cancels_pending_joins_running_and_never_returns_partial_rows(self):
        import threading
        with tempfile.TemporaryDirectory(dir=PROJECT/'tmp',prefix='stopped-reader-failure-') as tmp:
            driver=self.model(Path(tmp));entered=threading.Event();released=threading.Event();finished=threading.Event();started=[]
            class ExactRefusal(ValueError):pass
            def read(label,n):
                started.append((label,n))
                if (label,n)==SLOTS[0]:
                    entered.set();self.assertTrue(released.wait(2));time.sleep(.03);finished.set();return 'complete'
                self.assertEqual((label,n),SLOTS[1]);self.assertTrue(entered.wait(2));released.set()
                raise ExactRefusal('original full Native refusal model')
            with self.assertRaisesRegex(ExactRefusal,'original full Native refusal model'):
                driver.stopped_reads(SLOTS,read)
            self.assertTrue(finished.is_set());self.assertEqual(set(started),set(SLOTS[:2]))
    def test_duplicate_slots_shared_custody_and_expired_budget_refuse_before_read(self):
        for why in ('duplicate','signer','caller','expired'):
            with self.subTest(why=why),tempfile.TemporaryDirectory(dir=PROJECT/'tmp',prefix='stopped-reader-alias-') as tmp:
                driver=self.model(Path(tmp));slots=SLOTS[:2];read=[]
                if why=='duplicate':slots=(SLOTS[0],SLOTS[0])
                elif why=='expired':driver.deadline=time.monotonic()-1
                else:
                    first=json.loads(driver.configs[PHASES[-1],*SLOTS[0]].bft)
                    second=json.loads(driver.configs[PHASES[-1],*SLOTS[1]].bft)
                    field='signer_dir' if why=='signer' else 'head_file';second[field]=first[field]
                    old=driver.configs[PHASES[-1],*SLOTS[1]]
                    driver.configs[PHASES[-1],*SLOTS[1]]=Config(old.phase,old.region,old.index,old.started,old.mesh,encoded(second),old.argv)
                with self.assertRaises(ValueError):driver.stopped_reads(slots,lambda *slot:read.append(slot))
                self.assertFalse(read)





class StartupPinDriverTests(unittest.TestCase):
    def driver(self,root):
        d=Driver.__new__(Driver);d.root=root;d.output=root/'output';d.output.mkdir(mode=0o700)
        d.phase=PHASES[2];d.processes={};d.keyless_startup={};d.configs={}
        d.terminal=[dict(region=r,index=n,exit_code=0) for r,n in SLOTS]
        d.deadline=time.monotonic()+60;d.pins=[]
        absent=root/'absent';absent.mkdir(mode=0o700)
        for r,n in SLOTS:
            config=dict(key_file=str(absent/f'{r}-{n}.json'),state=str(root/f'state-{r}-{n}'))
            original=d.output/PHASES[-1]/f'bft-{r}-{n}.json';original.parent.mkdir(mode=0o700,exist_ok=True)
            mesh.atomic(original,config)
            d.configs[PHASES[-1],r,n]=Config(PHASES[-1],r,n,True,b'{}',original.read_bytes(),
                ('unused','--bft-config',str(original),'--unchanged','literal'))
        def pin(r,n,prefix,*,retain_stopped=True):
            self.assertFalse(retain_stopped)
            d.pins.append((r,n));return dict(history_head=f'{len(d.pins):064x}')
        d.pin_head=pin;return d

    def test_all12_pins_precede_config_derivation_and_original_bytes_argv_stay_exact(self):
        with tempfile.TemporaryDirectory(dir=PROJECT/'tmp') as tmp:
            d=self.driver(Path(tmp));original=dict(d.configs)
            file=d.file
            def write(name,value):
                self.assertEqual(d.pins,list(SLOTS));return file(name,value)
            d.file=write;d.prepare_keyless_startup()
            self.assertEqual(d.configs,original);self.assertEqual(set(d.keyless_startup),set(SLOTS))
            for slot in SLOTS:
                conf=original[PHASES[-1],*slot];row=d.keyless_startup[slot]
                config=json.loads(conf.bft);derived=json.loads(row['path'].read_bytes())
                self.assertEqual(set(derived)-set(config),{'startup_native_history_head'})
                self.assertEqual({k:derived[k] for k in config},config)
                argv=list(conf.argv);argv[argv.index('--bft-config')+1]=str(row['path'])
                self.assertEqual(tuple(argv),row['argv'])
                self.assertEqual(Path(conf.argv[2]).read_bytes(),conf.bft)
            with self.assertRaises(ValueError):d.prepare_keyless_startup()

    def test_unsafe_stop_partial_pin_wrong_argv_or_bound_config_refuse_without_launch(self):
        for why in ('active','unclean','wrong-phase','missing-slot','pin-failure','changed-config','wrong-argv'):
            with self.subTest(why=why),tempfile.TemporaryDirectory(dir=PROJECT/'tmp') as tmp:
                d=self.driver(Path(tmp))
                if why=='active':d.processes[('earth',0)]=object()
                elif why=='unclean':d.terminal[-1]['exit_code']=1
                elif why=='wrong-phase':d.phase=PHASES[-1]
                elif why=='missing-slot':d.terminal.pop()
                elif why=='pin-failure':
                    def fail(*args,**kwargs):raise ValueError('original pin refusal')
                    d.pin_head=fail
                elif why=='changed-config':Path(d.configs[PHASES[-1],'earth',0].argv[2]).write_bytes(b'{}')
                else:
                    c=d.configs[PHASES[-1],'earth',0]
                    d.configs[PHASES[-1],'earth',0]=Config(c.phase,c.region,c.index,c.started,c.mesh,c.bft,('unused',))
                with self.assertRaises(ValueError):d.prepare_keyless_startup()
                self.assertEqual(d.keyless_startup,{})

    def test_warm_startup_pin_never_populates_post_keyless_terminal_head_collection(self):
        d=Driver.__new__(Driver);d.processes={};d.stopped_heads={}
        d.regions={'earth':'2'*64};d.currency='1'*64
        head={'history_head':'3'*64};d.call=lambda *a:dict(head);d.file=lambda *a:None
        d.native=lambda *a:None
        checked=dict(region='2'*64,height=12)
        with patch('regional_paged_fault_driver.checked_history',return_value=checked):
            self.assertEqual(d.pin_head('earth',0,'startup',retain_stopped=False),head)
            self.assertEqual(d.stopped_heads,{})
            self.assertEqual(d.pin_head('earth',0,'stopped'),head)
            self.assertEqual(d.stopped_heads,{('earth',0):head['history_head']})

    def test_actual_launch_uses_bound_derived_argv_and_changed_bytes_refuse_before_spawn(self):
        with tempfile.TemporaryDirectory(dir=PROJECT/'tmp') as tmp:
            d=self.driver(Path(tmp));d.prepare_keyless_startup();d.phase=PHASES[-1]
            d.project=PROJECT;d.logs={};d.starts=0;d.record=lambda *a,**kw:None
            slot=('earth',0);seen=[]
            def spawn(argv,**kw):
                seen.append((argv,kw));return SimpleNamespace(pid=123)
            with patch('regional_paged_fault_driver.subprocess.Popen',spawn):d.start(d.phase,[slot])
            try:
                self.assertEqual(seen[0][0],d.keyless_startup[slot]['argv'])
                self.assertEqual(seen[0][1]['cwd'],PROJECT)
                self.assertEqual(d.starts,1)
            finally:d.logs[slot].close()
            other=('earth',1);d.keyless_startup[other]['path'].write_bytes(b'{}')
            with patch('regional_paged_fault_driver.subprocess.Popen',side_effect=AssertionError('no launch')):
                with self.assertRaises(ValueError):d.start(d.phase,[other])
            self.assertEqual(d.starts,1)

if __name__=='__main__':unittest.main()
