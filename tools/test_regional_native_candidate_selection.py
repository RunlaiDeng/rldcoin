"""Fresh no-value native selection, exact Python reference and real BFT payment.

The controller's quorum/inclusion checks are ground engineering evidence; it is
not an independent operator set, ordinary network fault profile or latency proof.
"""
import copy
import fcntl
import hashlib
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_candidate import select
from regional_bft_candidate_reference import candidate_reference
from regional_bft_network_campaign import Campaign
from regional_bft_node import Runtime
from regional_contact_campaign import public,seeds
from regional_contact_node import Native,NativeRefusal

BINARY=Path(os.environ.get('RLD_CONTACT_BINARY',str(Path(__file__).parent/'regional-ledger/target/debug/rld-regional-ledger-candidate'))).resolve()


class NativeSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='rld-native-selection-');self.root=Path(self.temp.name).resolve()/'fixture'
        self.c=Campaign(BINARY,self.root);self.runtime=None
        # The third and last reward is created at height 3 and matures at 5.
        for _ in range(5):self.c.checkpoint('earth',online=(0,1,2,3))
        self.native=Native(BINARY,self.c.node('earth',1),public(1),self.c.currency)
        self.wallet=self.root/'owner-wallet';self.owner_head=self.native.call('wallet-init','--wallet-dir',self.wallet,'--owner',public(10))['wallet_head']
        self.key=self.c.file('public-owner-key',{'secret_key':bytes([10]*32).hex()});self.key.chmod(0o600)
        observation=self.native.call('wallet-view','--wallet-dir',self.wallet,'--expected-wallet-head',self.owner_head)
        self.assertEqual(observation['ledger']['spendable'],'300')
        # The helper deliberately caps issuance at 300: later mining cannot
        # supply six rewards. Split existing value through ordinary owner and
        # 3-of-4 certificate checks, then wait the unchanged two-block maturity.
        split=dict(owner=public(10),inputs=None,outputs=[dict(owner=public(10),amount='49') for _ in range(6)],remote=None,fee='1',valid_for_blocks=8)
        prepared=self.native.call('wallet-prepare','--wallet-dir',self.wallet,'--expected-wallet-head',self.owner_head,'--file',self.c.file('split-request',split))
        signed=self.native.call('wallet-sign','--wallet-dir',self.wallet,'--expected-wallet-head',self.owner_head,'--file',self.c.file('split-review',prepared),
            '--review',prepared['review_commitment'],'--key-file',self.key)
        self.owner_head=signed['wallet_head'];self.c.checkpoint('earth',commands=signed['commands'],online=(0,1,2,3))
        for _ in range(2):self.c.checkpoint('earth',online=(0,1,2,3))
        view=self.native.call('wallet-view','--wallet-dir',self.wallet,'--expected-wallet-head',self.owner_head)
        coins=[v['id'] for v in view['ledger']['coins'] if v['spendable_now'] and v['amount']=='49']
        self.assertGreaterEqual(len(coins),6);self.commands=[]
        for index,coin in enumerate(coins[:6]):
            request=dict(owner=public(10),inputs=[coin],outputs=[dict(owner=public(14),amount=str(10+index))],remote=None,fee='1',valid_for_blocks=8)
            prepared=self.native.call('wallet-prepare','--wallet-dir',self.wallet,'--expected-wallet-head',self.owner_head,'--file',self.c.file('owner-request',request))
            signed=self.native.call('wallet-sign','--wallet-dir',self.wallet,'--expected-wallet-head',self.owner_head,'--file',self.c.file('owner-review',prepared),
                '--review',prepared['review_commitment'],'--key-file',self.key)
            self.owner_head=signed['wallet_head'];self.commands.extend(signed['commands'])
        self.context=self.native.call('bft-context')['context']
        self.facade=Runtime.__new__(Runtime);self.facade.native=self.native;self.facade.root=self.root;self.facade.miner=public(10);self.facade.joint=None
        self.actions=[];ordinary=self.facade.native
        class Tracked:
            def __getattr__(inner,name):return getattr(ordinary,name)
            def call(inner,action,*args,**kwargs):
                self.actions.append(action);return ordinary.call(action,*args,**kwargs)
        self.facade.native=Tracked()

    def tearDown(self):
        if self.runtime:self.runtime.close()
        self.c.cleanup();self.temp.cleanup()

    def custody(self):
        roots=[self.c.node('earth',1),self.wallet]+[self.c.signer('earth',i) for i in range(4)]
        return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for root in roots for p in root.rglob('*') if p.is_file()}

    def reference(self,incoming):
        ref=Runtime.__new__(Runtime);ref.native=self.native;ref.root=self.root;ref.miner=public(10);ref.joint=None
        ref.state={'messages':SimpleNamespace(bodies=lambda:[('reference',{'Submission':incoming},None,False)])}
        return candidate_reference(ref,self.context)

    def check_input_prefix_and_codec_refusals(self):
        base=dict(context=self.context,selected=[],seen=[],commands=[]);before=self.custody()
        variants=[dict(base,unexpected=True),dict(base,commands=self.commands[:1]*17),
            dict(base,selected=self.commands[:1]),
            dict(base,selected=self.commands[:1]*2,seen=[mesh.digest(self.commands[0])]),
            dict(base,context=dict(self.context,parent_height=True)),
            dict(base,selected=[{'Import':{'snapshot':'1'*64,'export':'2'*64}}],
                 seen=[mesh.digest({'Import':{'snapshot':'1'*64,'export':'2'*64}})])]
        for value in variants:
            with self.assertRaises(NativeRefusal):
                self.facade.with_json('bft-candidate-select',value,'--miner',public(10))
        path=self.c.file('duplicate-native-input',base)
        path.write_bytes(wire.canonical(base)[:-1]+b',"commands":[]}')
        with self.assertRaises(NativeRefusal):self.native.call('bft-candidate-select','--file',path,'--miner',public(10))
        self.assertEqual(before,self.custody());self.actions.clear()

    def check_order_duplicates_invalid_inputs_and_four_slots_match_independent_reference(self):
        invalid=[{'Import':{'snapshot':f'{n+1:064x}','export':f'{n+100:064x}'}} for n in range(18)]
        incoming=invalid+self.commands[:1]*2+self.commands[1:]
        original=copy.deepcopy(incoming);before=self.custody()
        expected=self.reference(incoming);actual=select(self.facade,self.context,incoming)
        self.assertEqual(wire.canonical(actual),wire.canonical(expected))
        self.assertEqual(actual['blocks'][-1]['commands'],self.commands[:4]);self.assertEqual(incoming,original)
        self.assertEqual(before,self.custody());self.assertEqual(self.actions,['bft-candidate-select','bft-candidate-select','bft-candidate'])

    def check_stale_context_and_real_native_lock_never_return_partial_or_sign(self):
        stale=dict(self.context,parent_height=self.context['parent_height']+1);before=self.custody()
        with self.assertRaises(NativeRefusal):select(self.facade,stale,self.commands)
        self.assertEqual(self.actions,['bft-candidate-select']);self.assertEqual(before,self.custody())
        self.actions.clear()
        with (self.native.ledger/'LOCK').open('r+b') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(NativeRefusal):select(self.facade,self.context,self.commands)
        self.assertEqual(self.actions,['bft-candidate-select']);self.assertEqual(before,self.custody())

    def check_changed_native_context_between_batches_refuses_without_final_candidate(self):
        ordinary=self.facade.native;calls=[]
        class Advance:
            def __getattr__(inner,name):return getattr(ordinary,name)
            def call(inner,action,*args,**kwargs):
                result=ordinary.call(action,*args,**kwargs);calls.append(action)
                if len(calls)==1:self.c.checkpoint('earth',online=(0,1,2,3))
                return result
        self.facade.native=Advance();before=self.wallet.joinpath('wallet.json').read_bytes()
        invalid=[{'Import':{'snapshot':f'{n+1:064x}','export':f'{n+100:064x}'}} for n in range(16)]
        with self.assertRaises(NativeRefusal):select(self.facade,self.context,invalid+self.commands)
        self.assertEqual(self.actions,['bft-candidate-select','bft-candidate-select'])
        self.assertEqual(before,self.wallet.joinpath('wallet.json').read_bytes())

    def check_production_runtime_native_proposal_certified_payment_and_cold_restart(self):
        keys=self.native.call('bft-context')['keys'];leader=keys[self.context['parent_height']%4]
        index=next(i for i,s in enumerate(seeds('earth')) if public(s)==leader)
        native=Native(BINARY,self.c.node('earth',index),public(1),self.c.currency)
        config=self.c.configs[index];config=dict(config,stop_height=16)
        path=self.c.file('selected-runtime-config',config)
        path.chmod(0o600)
        head=Path(config['head_file']);prior=mesh.load(head,8192);mesh.atomic(head,dict(prior,head=self.c.heads['earth',index]))
        native.call('bft-submit','--file',self.c.file('submitted-payment',self.commands[:1]))
        self.runtime=runtime=Runtime(native,mesh.load(self.root/f'mesh-config-{index}.json',65536),path)
        actions=[];ordinary=runtime.native
        class Track:
            def __getattr__(inner,name):return getattr(ordinary,name)
            def call(inner,action,*args,**kwargs):actions.append(action);return ordinary.call(action,*args,**kwargs)
        runtime.native=Track();runtime.tick()
        # First ordinary tick establishes this parent's slot and original
        # timer. Wait its real interval; never fabricate or rebase its clock.
        time.sleep(config['block_interval']+.05);runtime.tick()
        self.assertIn('bft-candidate-select',actions)
        self.assertIn('bft-proposal-opportunity',actions)
        self.assertIn('bft-phase-action',actions)
        proposal=runtime.signed(self.context,0,'Proposal')[0][0]
        self.assertEqual(proposal['snapshot']['blocks'][-1]['commands'],self.commands[:1])
        self.c.heads['earth',index]=runtime.head['head']
        online=[i for i in range(4) if i!=index]
        prepared=self.c.combine('earth',[self.c.sign('earth',i,{'Prepare':proposal})['message']['Vote'] for i in online])
        committed=self.c.combine('earth',[self.c.sign('earth',i,{'Commit':{'proposal':proposal,'prepared':prepared}})['message']['Vote'] for i in online])
        certificate=self.c.cli('earth',1,'bft-certify','--file',self.c.file('native-certification',dict(proposal=proposal,prepared=prepared,committed=committed)))
        for i in range(4):self.c.cli('earth',i,'finalize','--file',self.c.file('native-inclusion',certificate))
        runtime.close();self.runtime=None
        self.runtime=Runtime(native,mesh.load(self.root/f'mesh-config-{index}.json',65536),path)
        self.assertEqual(self.runtime.state['height'],self.context['parent_height']+1)
        view=self.native.call('wallet-view','--wallet-dir',self.wallet,'--expected-wallet-head',self.owner_head)
        self.assertEqual(view['signed'][1]['state'],'INCLUDED_IN_LOCAL_LEDGER')
        self.assertEqual(sum(s['state']=='INCLUDED_IN_LOCAL_LEDGER' for s in view['signed']),2)
        self.c.audit('native selection production proposal, certificate inclusion and cold restart')
        self.runtime.close();self.runtime=None
        for _ in range(2):self.c.checkpoint('earth',online=(0,1,2,3))
        recipient=self.root/'recipient-wallet'
        recipient_head=self.native.call('wallet-init','--wallet-dir',recipient,'--owner',public(14))['wallet_head']
        observed=self.native.call('wallet-view','--wallet-dir',recipient,'--expected-wallet-head',recipient_head)
        self.assertEqual(observed['ledger']['spendable'],'10')
        request=dict(owner=public(14),inputs=None,outputs=[dict(owner=public(15),amount='7')],remote=None,fee='1',valid_for_blocks=8)
        prepared=self.native.call('wallet-prepare','--wallet-dir',recipient,'--expected-wallet-head',recipient_head,'--file',self.c.file('second-owner-request',request))
        key=self.c.file('public-recipient-key',{'secret_key':bytes([14]*32).hex()});key.chmod(0o600)
        signed=self.native.call('wallet-sign','--wallet-dir',recipient,'--expected-wallet-head',recipient_head,'--file',self.c.file('second-owner-review',prepared),
            '--review',prepared['review_commitment'],'--key-file',key)
        context=self.native.call('bft-context')['context'];index=context['parent_height']%4
        native=Native(BINARY,self.c.node('earth',index),public(1),self.c.currency)
        config=dict(self.c.configs[index],stop_height=16);path=self.c.file('second-runtime-config',config);path.chmod(0o600)
        head=Path(config['head_file']);mesh.atomic(head,dict(mesh.load(head,8192),head=self.c.heads['earth',index]))
        native.call('bft-submit','--file',self.c.file('second-submission',signed['commands']))
        self.runtime=runtime=Runtime(native,mesh.load(self.root/f'mesh-config-{index}.json',65536),path)
        runtime.tick();time.sleep(config['block_interval']+.05);runtime.tick()
        proposal=runtime.signed(context,0,'Proposal')[0][0]
        self.assertEqual(proposal['snapshot']['blocks'][-1]['commands'],signed['commands'])
        self.c.heads['earth',index]=runtime.head['head'];online=[i for i in range(4) if i!=index]
        prepared_qc=self.c.combine('earth',[self.c.sign('earth',i,{'Prepare':proposal})['message']['Vote'] for i in online])
        committed_qc=self.c.combine('earth',[self.c.sign('earth',i,{'Commit':{'proposal':proposal,'prepared':prepared_qc}})['message']['Vote'] for i in online])
        certificate=self.c.cli('earth',1,'bft-certify','--file',self.c.file('second-certification',dict(proposal=proposal,prepared=prepared_qc,committed=committed_qc)))
        for i in range(4):self.c.cli('earth',i,'finalize','--file',self.c.file('second-inclusion',certificate))
        runtime.close();self.runtime=None
        self.runtime=Runtime(native,mesh.load(self.root/f'mesh-config-{index}.json',65536),path)
        self.assertEqual(self.runtime.state['height'],context['parent_height']+1)
        view=self.native.call('wallet-view','--wallet-dir',recipient,'--expected-wallet-head',signed['wallet_head'])
        self.assertEqual(view['signed'][0]['state'],'INCLUDED_IN_LOCAL_LEDGER');self.assertEqual(view['reserved_owned_outputs'],'0')
        self.c.audit('mature native recipient second Runtime payment, full certificate and cold restart')

    def test_complete_native_selection_and_payment_trajectory(self):
        self.check_input_prefix_and_codec_refusals()
        self.check_order_duplicates_invalid_inputs_and_four_slots_match_independent_reference()
        self.actions.clear()
        self.check_stale_context_and_real_native_lock_never_return_partial_or_sign()
        self.actions.clear()
        self.check_changed_native_context_between_batches_refuses_without_final_candidate()
        self.context=self.native.call('bft-context')['context']
        self.check_production_runtime_native_proposal_certified_payment_and_cold_restart()


if __name__=='__main__':unittest.main()
